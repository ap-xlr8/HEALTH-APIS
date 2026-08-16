package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/mongo"

	"healthos/backend/internal/authz"
	"healthos/backend/internal/models"
	"healthos/backend/internal/store"
	"healthos/backend/pkg/email"
	"healthos/backend/pkg/httpx"
	"healthos/backend/pkg/security"
)

type Store interface {
	CreateUser(ctx context.Context, user models.User) error
	FindUserByEmail(ctx context.Context, email string) (models.User, error)
	FindUserByID(ctx context.Context, id string) (models.User, error)
	FindUserByVerificationToken(ctx context.Context, token string) (models.User, error)
	VerifyUserEmail(ctx context.Context, token string) (models.User, error)
	UpdateUserFailedLogins(ctx context.Context, userID string, attempts int, lockoutUntil *time.Time) error
	ResetUserFailedLogins(ctx context.Context, userID string) error
	CreateSession(ctx context.Context, session models.Session) error
	FindSessionByID(ctx context.Context, id string) (models.Session, error)
	DeleteSessionByID(ctx context.Context, id string) error
	DeleteSessionsByUserID(ctx context.Context, userID string) error
}

type Handler struct {
	store       Store
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	emailSender email.Sender
}

func New(store Store, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, emailSender email.Sender) Handler {
	return Handler{
		store:       store,
		privateKey:  privateKey,
		publicKey:   publicKey,
		emailSender: emailSender,
	}
}

type registerRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	Role      string `json:"role"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type verifyEmailRequest struct {
	Token string `json:"token"`
}

func (h Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.FirstName = strings.TrimSpace(req.FirstName)
	req.LastName = strings.TrimSpace(req.LastName)
	if err := validateRegister(req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	passwordHash, err := security.HashPassword(req.Password)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "password hashing failed")
		return
	}

	verificationToken := "vtok_" + uuid.NewString()
	otpCode := generate6DigitOTP()
	expiresAt := time.Now().UTC().Add(24 * time.Hour)

	user := models.User{
		ID:                    "usr_" + uuid.NewString(),
		Email:                 req.Email,
		PasswordHash:          passwordHash,
		Role:                  req.Role,
		FirstName:             req.FirstName,
		LastName:              req.LastName,
		EmailVerified:         false,
		VerificationToken:     verificationToken,
		VerificationExpiresAt: &expiresAt,
		CreatedAt:             time.Now().UTC(),
	}
	if err := h.store.CreateUser(r.Context(), user); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			httpx.WriteError(w, http.StatusConflict, "email already registered")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "user registration failed")
		return
	}

	if h.emailSender != nil {
		fullName := strings.TrimSpace(user.FirstName + " " + user.LastName)
		_ = h.emailSender.SendVerificationEmail(r.Context(), user.Email, fullName, verificationToken, otpCode)
	}

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"status": "success",
		"data": map[string]string{
			"user_id":            user.ID,
			"verification_token": verificationToken,
			"message":            "User registered successfully. Please check your email to verify your account.",
		},
	})
}

func (h Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var token string
	if r.Method == http.MethodPost && r.Header.Get("Content-Type") == "application/json" {
		var req verifyEmailRequest
		if err := httpx.DecodeJSON(r, &req); err == nil {
			token = strings.TrimSpace(req.Token)
		}
	}
	if token == "" {
		token = strings.TrimSpace(r.URL.Query().Get("token"))
	}
	if token == "" {
		httpx.WriteError(w, http.StatusBadRequest, "verification token is required")
		return
	}

	user, err := h.store.VerifyUserEmail(r.Context(), token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteError(w, http.StatusBadRequest, "invalid or expired verification token")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "email verification failed")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"data": map[string]string{
			"user_id": user.ID,
			"message": "Email verified successfully. You can now login.",
		},
	})
}

func (h Handler) LoginMobile(w http.ResponseWriter, r *http.Request) {
	h.login(w, r, false)
}

func (h Handler) LoginWeb(w http.ResponseWriter, r *http.Request) {
	h.login(w, r, true)
}

func (h Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	refreshToken := ""
	if err := httpx.DecodeJSON(r, &req); err == nil {
		refreshToken = strings.TrimSpace(req.RefreshToken)
	}
	if refreshToken == "" {
		if cookie, err := r.Cookie("refresh_token"); err == nil {
			refreshToken = strings.TrimSpace(cookie.Value)
		}
	}
	if refreshToken == "" {
		httpx.WriteError(w, http.StatusBadRequest, "refresh token is required")
		return
	}

	claims, err := security.VerifyJWT(h.publicKey, refreshToken)
	if err != nil || claims.Kind != "refresh" || claims.ID == "" {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}
	session, err := h.store.FindSessionByID(r.Context(), claims.ID)
	if err != nil || session.UserID != claims.UserID || session.Kind != "refresh" || session.ExpiresAt.Before(time.Now().UTC()) {
		httpx.WriteError(w, http.StatusUnauthorized, "refresh token has been revoked")
		return
	}
	user, err := h.store.FindUserByID(r.Context(), claims.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusUnauthorized, "refresh token user is invalid")
		return
	}
	if err := h.store.DeleteSessionByID(r.Context(), claims.ID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "refresh rotation failed")
		return
	}
	access, _, err := security.SignJWT(h.privateKey, user.ID, user.Role, "access", 15*time.Minute)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "token signing failed")
		return
	}
	refresh, refreshID, err := security.SignJWT(h.privateKey, user.ID, user.Role, "refresh", 7*24*time.Hour)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "token signing failed")
		return
	}
	now := time.Now().UTC()
	if err := h.store.CreateSession(r.Context(), models.Session{
		ID:        refreshID,
		UserID:    user.ID,
		Kind:      "refresh",
		ExpiresAt: now.Add(7 * 24 * time.Hour),
		CreatedAt: now,
	}); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "refresh session persistence failed")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refresh,
		Path:     "/v1/auth",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  now.Add(7 * 24 * time.Hour),
	})

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"refresh_token": refresh,
		"expires_in":    900,
	})
}

func (h Handler) login(w http.ResponseWriter, r *http.Request, web bool) {
	var req loginRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	user, err := h.store.FindUserByEmail(r.Context(), email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "login lookup failed")
		return
	}

	now := time.Now().UTC()
	if user.LockoutUntil != nil && user.LockoutUntil.After(now) {
		httpx.WriteError(w, http.StatusTooManyRequests, "account temporarily locked due to multiple failed login attempts; try again later")
		return
	}

	if !security.CheckPassword(user.PasswordHash, req.Password) {
		attempts := user.FailedLoginAttempts + 1
		var lockoutUntil *time.Time
		if attempts >= 5 {
			l := now.Add(15 * time.Minute)
			lockoutUntil = &l
		}
		_ = h.store.UpdateUserFailedLogins(r.Context(), user.ID, attempts, lockoutUntil)
		httpx.WriteError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if !user.EmailVerified && user.Role != models.RoleAdmin {
		httpx.WriteJSON(w, http.StatusForbidden, map[string]any{
			"status":  "error",
			"message": "email is not verified; please verify your email before logging in",
			"data": map[string]string{
				"verification_token": user.VerificationToken,
				"email":              user.Email,
			},
			"error": map[string]string{
				"code":    "email_not_verified",
				"message": "email is not verified; please verify your email before logging in",
			},
		})
		return
	}

	if user.FailedLoginAttempts > 0 || user.LockoutUntil != nil {
		_ = h.store.ResetUserFailedLogins(r.Context(), user.ID)
	}

	access, _, err := security.SignJWT(h.privateKey, user.ID, user.Role, "access", 15*time.Minute)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "token signing failed")
		return
	}
	refresh, refreshID, err := security.SignJWT(h.privateKey, user.ID, user.Role, "refresh", 7*24*time.Hour)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "token signing failed")
		return
	}

	if err := h.store.CreateSession(r.Context(), models.Session{
		ID:        refreshID,
		UserID:    user.ID,
		Kind:      "refresh",
		ExpiresAt: now.Add(7 * 24 * time.Hour),
		CreatedAt: now,
	}); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "refresh session persistence failed")
		return
	}

	if web {
		csrf := uuid.NewString()
		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    access,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Expires:  now.Add(15 * time.Minute),
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    refresh,
			Path:     "/v1/auth",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Expires:  now.Add(7 * 24 * time.Hour),
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "csrf_token",
			Value:    csrf,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Expires:  now.Add(15 * time.Minute),
		})
		httpx.WriteJSON(w, http.StatusOK, map[string]string{
			"status":     "success",
			"csrf_token": csrf,
			"message":    "Logged in successfully",
		})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"refresh_token": refresh,
		"expires_in":    900,
	})
}

func (h Handler) LogoutWeb(w http.ResponseWriter, r *http.Request) {
	if claims, ok := authz.ClaimsFromContext(r.Context()); ok && claims != nil {
		_ = h.store.DeleteSessionsByUserID(r.Context(), claims.UserID)
	}
	now := time.Now().UTC().Add(-24 * time.Hour)
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  now,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/v1/auth",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  now,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  now,
		MaxAge:   -1,
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "Logged out successfully",
	})
}

func (h Handler) LogoutMobile(w http.ResponseWriter, r *http.Request) {
	if claims, ok := authz.ClaimsFromContext(r.Context()); ok && claims != nil {
		_ = h.store.DeleteSessionsByUserID(r.Context(), claims.UserID)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "Logged out successfully",
	})
}


func (h Handler) Me(w http.ResponseWriter, r *http.Request) {
	claims, ok := authz.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	user, err := h.store.FindUserByID(r.Context(), claims.UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "user not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "failed to get user profile")
		return
	}
	name := strings.TrimSpace(user.FirstName + " " + user.LastName)
	if name == "" {
		name = user.Email
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id":         user.ID,
		"email":      user.Email,
		"name":       name,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"role":       user.Role,
		"created_at": user.CreatedAt,
	})
}

func generate6DigitOTP() string {
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return "123456"
	}
	return fmt.Sprintf("%06d", n.Int64()+100000)
}

func validateRegister(req registerRequest) error {
	if _, err := mail.ParseAddress(req.Email); err != nil {
		return errors.New("email must be valid")
	}
	if req.Role != models.RolePatient && req.Role != models.RoleCaregiver {
		return errors.New("role must be patient or caregiver")
	}
	if len(req.FirstName) < 1 || len(req.FirstName) > 80 || len(req.LastName) < 1 || len(req.LastName) > 80 {
		return errors.New("first_name and last_name are required and must be <= 80 characters")
	}
	if len(req.Password) < 9 || len(req.Password) > 128 {
		return errors.New("password must be between 9 and 128 characters")
	}
	if !regexp.MustCompile(`[0-9]`).MatchString(req.Password) || !regexp.MustCompile(`[^A-Za-z0-9]`).MatchString(req.Password) {
		return errors.New("password must include a number and a symbol")
	}
	return nil
}

