package authz

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"
	"strings"

	"healthos/backend/internal/abac"
	"healthos/backend/internal/audit"
	"healthos/backend/internal/models"
	"healthos/backend/internal/rbac"
	"healthos/backend/internal/store"
	"healthos/backend/pkg/httpx"
	"healthos/backend/pkg/security"
)

type contextKey string

const claimsKey contextKey = "claims"

func isStateChangingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

type Store interface {
	FindUserByID(ctx context.Context, id string) (models.User, error)
	HasActiveRelationship(ctx context.Context, caregiverID, patientID string) (bool, error)
	HasConsentScope(ctx context.Context, caregiverID, patientID, scope string) (bool, error)
	WriteAudit(ctx context.Context, log models.AuditLog) error
}

type Middleware struct {
	publicKey *rsa.PublicKey
	store     Store
}

func New(publicKey *rsa.PublicKey, store Store) Middleware {
	return Middleware{publicKey: publicKey, store: store}
}

func WithClaims(ctx context.Context, claims *security.Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

func ClaimsFromContext(ctx context.Context) (*security.Claims, bool) {
	claims, ok := ctx.Value(claimsKey).(*security.Claims)
	return claims, ok
}

func (m Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := httpx.BearerToken(r)
		fromCookie := false
		if token == "" {
			if cookie, err := r.Cookie("access_token"); err == nil {
				token = strings.TrimSpace(cookie.Value)
				fromCookie = true
			}
		}
		if token == "" {
			httpx.WriteError(w, http.StatusUnauthorized, "missing access token")
			return
		}
		if m.publicKey == nil {
			httpx.WriteError(w, http.StatusInternalServerError, "jwt verifier is not configured")
			return
		}
		claims, err := security.VerifyJWT(m.publicKey, token)
		if err != nil {
			httpx.WriteError(w, http.StatusUnauthorized, "invalid access token")
			return
		}
		if claims.Kind != "access" {
			httpx.WriteError(w, http.StatusUnauthorized, "invalid access token kind")
			return
		}
		if fromCookie {
			csrfCookie, err := r.Cookie("csrf_token")
			if err == nil && csrfCookie.Value != "" {
				// Expose the current CSRF token so the SPA can re-acquire it after a reload
				w.Header().Set("X-CSRF-Token", csrfCookie.Value)
			}
			if isStateChangingMethod(r.Method) {
				if err != nil || csrfCookie.Value == "" || csrfCookie.Value != r.Header.Get("X-CSRF-Token") {
					httpx.WriteError(w, http.StatusForbidden, "invalid csrf token")
					return
				}
			}
		}
		next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
	})
}

func (m Middleware) Authorize(resource, scope string, allowedRoles []string, patientIDFromRequest func(*http.Request) string, next http.Handler) http.Handler {
	return m.AuthorizeResolved(resource, scope, allowedRoles, func(r *http.Request) (string, error) {
		return patientIDFromRequest(r), nil
	}, next)
}

func (m Middleware) AuthorizeResolved(resource, scope string, allowedRoles []string, patientIDFromRequest func(*http.Request) (string, error), next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok {
			httpx.WriteError(w, http.StatusUnauthorized, "missing authenticated principal")
			return
		}
		patientID, err := patientIDFromRequest(r)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				httpx.WriteError(w, http.StatusNotFound, resource+" not found")
				return
			}
			httpx.WriteError(w, http.StatusInternalServerError, "authorization resource lookup failed")
			return
		}
		allowed, reason := m.evaluate(r.Context(), claims, patientID, scope, allowedRoles)
		_ = audit.NewRecorder(m.store).Record(r.Context(), audit.Entry{
			UserID:   claims.UserID,
			Action:   r.Method + " " + r.URL.Path,
			Resource: resource,
			Allowed:  allowed,
			Reason:   reason,
			Metadata: map[string]any{"patient_id": patientID, "scope": scope},
		})
		if !allowed {
			httpx.WriteError(w, http.StatusForbidden, reason)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m Middleware) evaluate(ctx context.Context, claims *security.Claims, patientID, scope string, allowedRoles []string) (bool, string) {
	user, err := m.store.FindUserByID(ctx, claims.UserID)
	if err != nil {
		if err == store.ErrNotFound {
			return false, "authenticated user no longer exists"
		}
		return false, "authorization lookup failed"
	}
	if user.Role != claims.Role {
		return false, "role mismatch"
	}
	if !rbac.NewPolicy(allowedRoles).Allows(user.Role) {
		return false, "role is not allowed for this route"
	}
	return abac.Decide(ctx, m.store, user, patientID, scope)
}
