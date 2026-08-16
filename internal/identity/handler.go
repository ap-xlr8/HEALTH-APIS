package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/mongo"

	"healthos/backend/internal/audit"
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
	SetUserTwoFactorCode(ctx context.Context, userID, code string, expiresAt time.Time) error
	VerifyUserTwoFactorCode(ctx context.Context, email, code string) (models.User, error)
	ClearUserTwoFactorCode(ctx context.Context, userID string) error
	UpdateUserFailedLogins(ctx context.Context, userID string, attempts int, lockoutUntil *time.Time) error
	ResetUserFailedLogins(ctx context.Context, userID string) error
	SetUserPasswordResetToken(ctx context.Context, userID, token string, expiresAt time.Time) error
	FindUserByPasswordResetToken(ctx context.Context, token string) (models.User, error)
	ResetUserPassword(ctx context.Context, token, passwordHash string) (models.User, error)
	CreateSession(ctx context.Context, session models.Session) error
	FindSessionByID(ctx context.Context, id string) (models.Session, error)
	DeleteSessionByID(ctx context.Context, id string) error
	DeleteSessionsByUserID(ctx context.Context, userID string) error
	WriteAudit(ctx context.Context, log models.AuditLog) error
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

func (h Handler) recordAudit(ctx context.Context, userID, action, resource string, allowed bool, reason string) {
	_ = audit.NewRecorder(h.store).Record(ctx, audit.Entry{
		UserID:   userID,
		Action:   action,
		Resource: resource,
		Allowed:  allowed,
		Reason:   reason,
	})
}

type registerRequest struct {
	Email            string                `json:"email"`
	Password         string                `json:"password"`
	Role             string                `json:"role"`
	FirstName        string                `json:"first_name"`
	LastName         string                `json:"last_name"`
	Age              int                   `json:"age"`
	HealthProfile    *models.HealthProfile `json:"health_profile"`
	ActiveConditions []string              `json:"active_conditions"`
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

type twoFactorVerifyRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

type twoFactorResendRequest struct {
	Email string `json:"email"`
}

type forgotPasswordRequest struct {
	Email string `json:"email"`
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
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

	otpCode, err := generate6DigitOTP()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to generate secure security code")
		return
	}
	expiresAt := time.Now().UTC().Add(10 * time.Minute)

	user := models.User{
		ID:                 "usr_" + uuid.NewString(),
		Email:              req.Email,
		PasswordHash:       passwordHash,
		Role:               req.Role,
		FirstName:          req.FirstName,
		LastName:           req.LastName,
		Age:                req.Age,
		HealthProfile:      req.HealthProfile,
		ActiveConditions:   req.ActiveConditions,
		EmailVerified:      true,
		TwoFactorCode:      otpCode,
		TwoFactorExpiresAt: &expiresAt,
		CreatedAt:          time.Now().UTC(),
	}
	if err := h.store.CreateUser(r.Context(), user); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			h.recordAudit(r.Context(), "", "auth.register", user.Email, false, "duplicate_email")
			httpx.WriteError(w, http.StatusConflict, "email already registered")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "user registration failed")
		return
	}
	h.recordAudit(r.Context(), user.ID, "auth.register", user.Email, true, "")

	if h.emailSender != nil {
		fullName := strings.TrimSpace(user.FirstName + " " + user.LastName)
		_ = h.emailSender.Send2FACode(r.Context(), user.Email, fullName, otpCode, "creación de cuenta")
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status":  "2fa_required",
		"message": "Código de verificación de 6 dígitos enviado a tu correo.",
		"data": map[string]any{
			"user_id":    user.ID,
			"email":      user.Email,
			"expires_in": 600,
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
			h.recordAudit(r.Context(), "", "auth.verify_email", "", false, "invalid_or_expired_token")
			httpx.WriteError(w, http.StatusBadRequest, "invalid or expired verification token")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "email verification failed")
		return
	}
	h.recordAudit(r.Context(), user.ID, "auth.verify_email", user.Email, true, "")

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

func (h Handler) Verify2FAMobile(w http.ResponseWriter, r *http.Request) {
	h.verify2FA(w, r, false)
}

func (h Handler) Verify2FAWeb(w http.ResponseWriter, r *http.Request) {
	h.verify2FA(w, r, true)
}

func (h Handler) Resend2FA(w http.ResponseWriter, r *http.Request) {
	var req twoFactorResendRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		httpx.WriteError(w, http.StatusBadRequest, "email is required")
		return
	}
	user, err := h.store.FindUserByEmail(r.Context(), email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.recordAudit(r.Context(), "", "auth.2fa_resend", email, false, "user_not_found")
			httpx.WriteError(w, http.StatusNotFound, "user not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "lookup failed")
		return
	}

	otpCode, err := generate6DigitOTP()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to generate secure security code")
		return
	}
	expiresAt := time.Now().UTC().Add(10 * time.Minute)
	if err := h.store.SetUserTwoFactorCode(r.Context(), user.ID, otpCode, expiresAt); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to update 2fa code")
		return
	}
	h.recordAudit(r.Context(), user.ID, "auth.2fa_resend", user.Email, true, "")

	if h.emailSender != nil {
		fullName := strings.TrimSpace(user.FirstName + " " + user.LastName)
		_ = h.emailSender.Send2FACode(r.Context(), user.Email, fullName, otpCode, "verificación de seguridad")
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status":     "success",
		"message":    "Nuevo código 2FA enviado a tu correo.",
		"expires_in": 600,
	})
}

func (h Handler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req forgotPasswordRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" || !strings.Contains(email, "@") {
		httpx.WriteError(w, http.StatusBadRequest, "email is required")
		return
	}

	user, err := h.store.FindUserByEmail(r.Context(), email)
	if err != nil {
		// Do not reveal whether an account exists for a given email.
		if errors.Is(err, store.ErrNotFound) {
			h.recordAudit(r.Context(), "", "auth.password_reset_request", email, false, "user_not_found")
			httpx.WriteJSON(w, http.StatusOK, map[string]any{
				"status":  "success",
				"message": "Si el correo está registrado, recibirás un enlace para restablecer tu contraseña.",
			})
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "password reset lookup failed")
		return
	}

	token, err := generateResetToken()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to generate secure reset token")
		return
	}
	expiresAt := time.Now().UTC().Add(30 * time.Minute)
	if err := h.store.SetUserPasswordResetToken(r.Context(), user.ID, token, expiresAt); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to store reset token")
		return
	}
	h.recordAudit(r.Context(), user.ID, "auth.password_reset_request", user.Email, true, "")

	if h.emailSender != nil {
		fullName := strings.TrimSpace(user.FirstName + " " + user.LastName)
		resetURL := passwordResetURL(r, token)
		_ = h.emailSender.SendPasswordReset(r.Context(), user.Email, fullName, resetURL)
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"message": "Si el correo está registrado, recibirás un enlace para restablecer tu contraseña.",
	})
}

func (h Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		httpx.WriteError(w, http.StatusBadRequest, "token is required")
		return
	}
	if err := validatePassword(req.NewPassword); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	passwordHash, err := security.HashPassword(req.NewPassword)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "password hashing failed")
		return
	}
	user, err := h.store.ResetUserPassword(r.Context(), token, passwordHash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.recordAudit(r.Context(), "", "auth.password_reset", "", false, "invalid_or_expired_token")
			httpx.WriteError(w, http.StatusBadRequest, "enlace de restablecimiento inválido o expirado (válido por 30 minutos)")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "password reset failed")
		return
	}
	h.recordAudit(r.Context(), user.ID, "auth.password_reset", user.Email, true, "")

	_ = h.store.DeleteSessionsByUserID(r.Context(), user.ID)
	_ = h.store.ClearUserTwoFactorCode(r.Context(), user.ID)
	_ = h.store.ResetUserFailedLogins(r.Context(), user.ID)

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"message": "Contraseña actualizada correctamente. Ya puedes iniciar sesión.",
	})
}

// ResetPasswordPage renders the self-contained password reset form. It is the
// destination of the link sent by email and does not depend on the web app URL.
func (h Handler) ResetPasswordPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		h.submitResetForm(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.renderResetForm(w, r, "")
}

func (h Handler) submitResetForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	token := strings.TrimSpace(r.PostForm.Get("token"))
	password := r.PostForm.Get("new_password")
	confirm := r.PostForm.Get("confirm_password")

	if token == "" {
		h.renderResetForm(w, r, "Enlace de restablecimiento inválido o incompleto.")
		return
	}
	if password == "" || password != confirm {
		h.renderResetForm(w, r, "Las contraseñas no coinciden.")
		return
	}
	if err := validatePassword(password); err != nil {
		h.renderResetForm(w, r, err.Error())
		return
	}

	passwordHash, err := security.HashPassword(password)
	if err != nil {
		h.renderResetForm(w, r, "No se pudo procesar la contraseña. Inténtalo de nuevo.")
		return
	}
	user, err := h.store.ResetUserPassword(r.Context(), token, passwordHash)
	if err != nil {
		h.recordAudit(r.Context(), "", "auth.password_reset", "", false, "invalid_or_expired_token")
		h.renderResetForm(w, r, "El enlace es inválido o ha expirado. Solicita uno nuevo.")
		return
	}
	h.recordAudit(r.Context(), user.ID, "auth.password_reset", user.Email, true, "")

	_ = h.store.DeleteSessionsByUserID(r.Context(), user.ID)
	_ = h.store.ClearUserTwoFactorCode(r.Context(), user.ID)
	_ = h.store.ResetUserFailedLogins(r.Context(), user.ID)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(resetSuccessHTML))
}

func (h Handler) renderResetForm(w http.ResponseWriter, r *http.Request, errorMessage string) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		token = strings.TrimSpace(r.PostForm.Get("token"))
	}
	if errorMessage == "" && token != "" {
		if _, err := h.store.FindUserByPasswordResetToken(r.Context(), token); err != nil {
			errorMessage = "El enlace es inválido o ha expirado. Solicita uno nuevo."
			token = ""
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	html := strings.ReplaceAll(resetFormHTML, "__TOKEN__", htmlEscape(token))
	html = strings.ReplaceAll(html, "__ERROR__", htmlEscape(errorMessage))
	_, _ = w.Write([]byte(html))
}

func (h Handler) verify2FA(w http.ResponseWriter, r *http.Request, web bool) {
	var req twoFactorVerifyRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	code := strings.TrimSpace(req.Code)
	if email == "" || code == "" {
		httpx.WriteError(w, http.StatusBadRequest, "email and code are required")
		return
	}

	user, err := h.store.VerifyUserTwoFactorCode(r.Context(), email, code)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			if existingUser, lookupErr := h.store.FindUserByEmail(r.Context(), email); lookupErr == nil {
				attempts := existingUser.FailedLoginAttempts + 1
				var lockout *time.Time
				if attempts >= 5 {
					_ = h.store.ClearUserTwoFactorCode(r.Context(), existingUser.ID)
					l := time.Now().UTC().Add(15 * time.Minute)
					lockout = &l
					_ = h.store.UpdateUserFailedLogins(r.Context(), existingUser.ID, attempts, lockout)
					h.recordAudit(r.Context(), existingUser.ID, "auth.2fa", email, false, "too_many_attempts")
					httpx.WriteError(w, http.StatusTooManyRequests, "demasiados intentos fallidos de 2FA; código invalidado, solicita uno nuevo")
					return
				}
				_ = h.store.UpdateUserFailedLogins(r.Context(), existingUser.ID, attempts, nil)
			}
			h.recordAudit(r.Context(), "", "auth.2fa", email, false, "invalid_code")
			httpx.WriteError(w, http.StatusUnauthorized, "código 2FA inválido o expirado (válido por 10 minutos)")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "2fa verification failed")
		return
	}
	h.recordAudit(r.Context(), user.ID, "auth.2fa", user.Email, true, "2fa_success")
	_ = h.store.ResetUserFailedLogins(r.Context(), user.ID)

	now := time.Now().UTC()
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
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"status":        "success",
			"csrf_token":    csrf,
			"access_token":  access,
			"refresh_token": refresh,
			"expires_in":    900,
			"message":       "2FA authentication successful",
		})
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"refresh_token": refresh,
		"expires_in":    900,
		"role":          user.Role,
	})
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
		h.recordAudit(r.Context(), "", "auth.token_refresh", "", false, "invalid_token")
		httpx.WriteError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}
	session, err := h.store.FindSessionByID(r.Context(), claims.ID)
	if err != nil || session.UserID != claims.UserID || session.Kind != "refresh" || session.ExpiresAt.Before(time.Now().UTC()) {
		h.recordAudit(r.Context(), claims.UserID, "auth.token_refresh", "", false, "revoked_session")
		httpx.WriteError(w, http.StatusUnauthorized, "refresh token has been revoked")
		return
	}
	user, err := h.store.FindUserByID(r.Context(), claims.UserID)
	if err != nil {
		h.recordAudit(r.Context(), claims.UserID, "auth.token_refresh", "", false, "user_not_found")
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
	h.recordAudit(r.Context(), user.ID, "auth.token_refresh", user.Email, true, "")

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
			h.recordAudit(r.Context(), "", "auth.login", email, false, "invalid_credentials")
			httpx.WriteError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "login lookup failed")
		return
	}

	now := time.Now().UTC()
	if user.LockoutUntil != nil && user.LockoutUntil.After(now) {
		h.recordAudit(r.Context(), user.ID, "auth.login", email, false, "account_locked")
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
		h.recordAudit(r.Context(), user.ID, "auth.login", email, false, "invalid_credentials")
		httpx.WriteError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if user.FailedLoginAttempts > 0 || user.LockoutUntil != nil {
		_ = h.store.ResetUserFailedLogins(r.Context(), user.ID)
	}

	otpCode, err := generate6DigitOTP()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to generate secure security code")
		return
	}
	expiresAt := now.Add(10 * time.Minute)
	if err := h.store.SetUserTwoFactorCode(r.Context(), user.ID, otpCode, expiresAt); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to generate 2fa challenge")
		return
	}
	h.recordAudit(r.Context(), user.ID, "auth.login", user.Email, true, "2fa_issued")

	if h.emailSender != nil {
		fullName := strings.TrimSpace(user.FirstName + " " + user.LastName)
		_ = h.emailSender.Send2FACode(r.Context(), user.Email, fullName, otpCode, "inicio de sesión")
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status":  "2fa_required",
		"message": "Código de seguridad de 6 dígitos enviado a tu correo.",
		"data": map[string]any{
			"user_id":    user.ID,
			"email":      user.Email,
			"expires_in": 600,
		},
	})
}

func (h Handler) LogoutWeb(w http.ResponseWriter, r *http.Request) {
	if claims, ok := authz.ClaimsFromContext(r.Context()); ok && claims != nil {
		_ = h.store.DeleteSessionsByUserID(r.Context(), claims.UserID)
		h.recordAudit(r.Context(), claims.UserID, "auth.logout", "", true, "")
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
		h.recordAudit(r.Context(), claims.UserID, "auth.logout", "", true, "")
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

func generate6DigitOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return "", fmt.Errorf("crypto random entropy failure: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()+100000), nil
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
	if err := validatePassword(req.Password); err != nil {
		return err
	}
	if req.Age < 0 || req.Age > 120 {
		return errors.New("age must be between 0 and 120")
	}
	if req.HealthProfile != nil {
		if req.HealthProfile.WeightKg < 20 || req.HealthProfile.WeightKg > 300 {
			return errors.New("health_profile.weight_kg must be between 20 and 300")
		}
		if req.HealthProfile.HeightCm < 50 || req.HealthProfile.HeightCm > 250 {
			return errors.New("health_profile.height_cm must be between 50 and 250")
		}
		if !validBloodType(req.HealthProfile.BloodType) {
			return errors.New("health_profile.blood_type must be one of A+, A-, B+, B-, AB+, AB-, O+, O-")
		}
	}
	if len(req.ActiveConditions) > 20 {
		return errors.New("active_conditions must not exceed 20 entries")
	}
	for _, condition := range req.ActiveConditions {
		if len(strings.TrimSpace(condition)) == 0 || len(condition) > 120 {
			return errors.New("each active condition must be between 1 and 120 characters")
		}
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 9 || len(password) > 128 {
		return errors.New("password must be between 9 and 128 characters")
	}
	if !regexp.MustCompile(`[0-9]`).MatchString(password) || !regexp.MustCompile(`[^A-Za-z0-9]`).MatchString(password) {
		return errors.New("password must include a number and a symbol")
	}
	return nil
}

func validBloodType(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-":
		return true
	default:
		return false
	}
}

func generateResetToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto random entropy failure: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func passwordResetURL(r *http.Request, token string) string {
	scheme := "https"
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "http") {
		scheme = "http"
	} else if r.TLS == nil && !strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") && r.Host != "" {
		// Local dev over plain http should stay on http.
		scheme = "http"
	}
	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = "localhost:8080"
	}
	return scheme + "://" + host + "/reset-password?token=" + url.QueryEscape(token)
}

func htmlEscape(value string) string {
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&#34;",
		"'", "&#39;",
	).Replace(value)
}

const resetFormHTML = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Restablecer contraseña - Health OS</title>
<style>
  body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; color: #1e293b; }
  .card { max-width: 420px; margin: 8vh auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 14px; padding: 32px; box-shadow: 0 8px 24px rgba(2, 132, 199, 0.06); }
  h1 { color: #0284c7; margin: 0 0 4px 0; font-size: 22px; letter-spacing: -0.5px; }
  .sub { color: #64748b; font-size: 13px; margin: 0 0 24px 0; }
  label { display: block; font-size: 13px; font-weight: 600; margin: 14px 0 6px 0; color: #334155; }
  input[type=password] { width: 100%; box-sizing: border-box; padding: 11px 12px; border: 1px solid #cbd5e1; border-radius: 8px; font-size: 14px; }
  input[type=password]:focus { outline: none; border-color: #0284c7; box-shadow: 0 0 0 3px rgba(2, 132, 199, 0.15); }
  button { width: 100%; margin-top: 22px; padding: 12px; background: #0284c7; color: #ffffff; border: none; border-radius: 8px; font-size: 15px; font-weight: 700; cursor: pointer; }
  button:hover { background: #0369a1; }
  .error { background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; border-radius: 8px; padding: 10px 14px; font-size: 13px; margin-bottom: 8px; }
  .hint { color: #94a3b8; font-size: 12px; margin-top: 8px; }
  .done { text-align: center; }
  .done a { color: #0284c7; font-weight: 600; }
</style>
</head>
<body>
  <div class="card">
    <h1>Health OS</h1>
    <p class="sub">Restablece tu contraseña</p>
    <div class="error">__ERROR__</div>
    <form method="POST" action="/reset-password">
      <input type="hidden" name="token" value="__TOKEN__">
      <label for="new_password">Nueva contraseña</label>
      <input type="password" id="new_password" name="new_password" minlength="9" maxlength="128" required autocomplete="new-password">
      <label for="confirm_password">Confirmar contraseña</label>
      <input type="password" id="confirm_password" name="confirm_password" minlength="9" maxlength="128" required autocomplete="new-password">
      <button type="submit">Actualizar contraseña</button>
      <p class="hint">Mínimo 9 caracteres, debe incluir al menos un número y un símbolo.</p>
    </form>
  </div>
</body>
</html>`

const resetSuccessHTML = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Contraseña actualizada - Health OS</title>
<style>
  body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; color: #1e293b; }
  .card { max-width: 420px; margin: 8vh auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 14px; padding: 32px; text-align: center; box-shadow: 0 8px 24px rgba(2, 132, 199, 0.06); }
  .icon { width: 56px; height: 56px; margin: 0 auto 16px auto; border-radius: 50%; background: #ecfdf5; color: #059669; font-size: 30px; line-height: 56px; font-weight: 800; }
  h1 { color: #0f766e; font-size: 20px; margin: 0 0 8px 0; }
  p { color: #64748b; font-size: 14px; line-height: 1.6; margin: 0 0 20px 0; }
  .btn { display: inline-block; background: #0284c7; color: #ffffff; text-decoration: none; font-weight: 700; font-size: 14px; padding: 11px 24px; border-radius: 8px; }
</style>
</head>
<body>
  <div class="card">
    <div class="icon">&#10003;</div>
    <h1>Contraseña actualizada</h1>
    <p>Tu contraseña se restableció correctamente. Ya puedes iniciar sesión en la aplicación.</p>
  </div>
</body>
</html>`
