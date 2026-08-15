package identity

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/mongo"

	"healthos/backend/internal/models"
	"healthos/backend/internal/store"
	"healthos/backend/pkg/httpx"
	"healthos/backend/pkg/security"
)

type Store interface {
	CreateUser(ctx context.Context, user models.User) error
	FindUserByEmail(ctx context.Context, email string) (models.User, error)
	FindUserByID(ctx context.Context, id string) (models.User, error)
	CreateSession(ctx context.Context, session models.Session) error
	FindSessionByID(ctx context.Context, id string) (models.Session, error)
	DeleteSessionByID(ctx context.Context, id string) error
}

type Handler struct {
	store      Store
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func New(store Store, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) Handler {
	return Handler{store: store, privateKey: privateKey, publicKey: publicKey}
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
	user := models.User{
		ID:           "usr_" + uuid.NewString(),
		Email:        req.Email,
		PasswordHash: passwordHash,
		Role:         req.Role,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		CreatedAt:    time.Now().UTC(),
	}
	if err := h.store.CreateUser(r.Context(), user); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			httpx.WriteError(w, http.StatusConflict, "email already registered")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "user registration failed")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"status": "success",
		"data": map[string]string{
			"user_id": user.ID,
			"message": "User registered successfully. Please verify your email.",
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
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	claims, err := security.VerifyJWT(h.publicKey, strings.TrimSpace(req.RefreshToken))
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
	if !security.CheckPassword(user.PasswordHash, req.Password) {
		httpx.WriteError(w, http.StatusUnauthorized, "invalid credentials")
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
