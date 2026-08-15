package authz

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"healthos/backend/internal/models"
	"healthos/backend/internal/store"
	"healthos/backend/pkg/security"
)

type fakeAuthzStore struct {
	user         models.User
	relationship bool
	consent      bool
	audit        *models.AuditLog
}

func (f fakeAuthzStore) FindUserByID(ctx context.Context, id string) (models.User, error) {
	if f.user.ID == id {
		return f.user, nil
	}
	return models.User{}, store.ErrNotFound
}

func (f fakeAuthzStore) HasActiveRelationship(ctx context.Context, caregiverID, patientID string) (bool, error) {
	return f.relationship, nil
}

func (f fakeAuthzStore) HasConsentScope(ctx context.Context, caregiverID, patientID, scope string) (bool, error) {
	return f.consent, nil
}

func (f fakeAuthzStore) WriteAudit(ctx context.Context, log models.AuditLog) error {
	if f.audit != nil {
		*f.audit = log
	}
	return nil
}

func TestEvaluatePatientOwnResource(t *testing.T) {
	t.Parallel()
	m := New(nil, fakeAuthzStore{user: models.User{ID: "usr_1", Role: models.RolePatient}})
	allowed, reason := m.evaluate(context.Background(), &security.Claims{UserID: "usr_1", Role: models.RolePatient}, "usr_1", models.ScopeReadPatient, []string{models.RolePatient})
	if !allowed || reason != "patient owns resource" {
		t.Fatalf("expected own-resource access, got allowed=%v reason=%q", allowed, reason)
	}
}

func TestEvaluateCaregiverRequiresRelationshipAndConsent(t *testing.T) {
	t.Parallel()
	m := New(nil, fakeAuthzStore{user: models.User{ID: "cg_1", Role: models.RoleCaregiver}, relationship: true, consent: false})
	allowed, reason := m.evaluate(context.Background(), &security.Claims{UserID: "cg_1", Role: models.RoleCaregiver}, "usr_1", models.ScopeReadPatient, []string{models.RoleCaregiver})
	if allowed || reason != "patient consent scope required" {
		t.Fatalf("expected consent denial, got allowed=%v reason=%q", allowed, reason)
	}
}

func TestEvaluateRoleDenied(t *testing.T) {
	t.Parallel()
	m := New(nil, fakeAuthzStore{user: models.User{ID: "cg_1", Role: models.RoleCaregiver}})
	allowed, reason := m.evaluate(context.Background(), &security.Claims{UserID: "cg_1", Role: models.RoleCaregiver}, "cg_1", models.ScopeReadMeasurements, []string{models.RolePatient})
	if allowed || reason != "role is not allowed for this route" {
		t.Fatalf("expected role denial, got allowed=%v reason=%q", allowed, reason)
	}
}

func TestEvaluateAdminAndMissingUser(t *testing.T) {
	t.Parallel()
	admin := New(nil, fakeAuthzStore{user: models.User{ID: "admin_1", Role: models.RoleAdmin}})
	allowed, reason := admin.evaluate(context.Background(), &security.Claims{UserID: "admin_1", Role: models.RoleAdmin}, "usr_1", models.ScopeReadPatient, []string{models.RoleAdmin})
	if !allowed || reason != "admin access" {
		t.Fatalf("expected admin access, got allowed=%v reason=%q", allowed, reason)
	}

	missing := New(nil, fakeAuthzStore{})
	allowed, reason = missing.evaluate(context.Background(), &security.Claims{UserID: "missing", Role: models.RolePatient}, "usr_1", models.ScopeReadPatient, []string{models.RolePatient})
	if allowed || reason != "authenticated user no longer exists" {
		t.Fatalf("expected missing user denial, got allowed=%v reason=%q", allowed, reason)
	}
}

func TestRequireAuthBearerAndAuthorize(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	token, _, err := security.SignJWT(privateKey, "usr_1", models.RolePatient, "access", time.Minute)
	if err != nil {
		t.Fatalf("SignJWT returned error: %v", err)
	}
	store := fakeAuthzStore{user: models.User{ID: "usr_1", Role: models.RolePatient}}
	middleware := New(&privateKey.PublicKey, store)
	called := false
	handler := middleware.RequireAuth(middleware.Authorize(
		"patients",
		models.ScopeReadPatient,
		[]string{models.RolePatient},
		func(*http.Request) string { return "usr_1" },
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		}),
	))
	req := httptest.NewRequest(http.MethodGet, "/v1/patients/usr_1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	if res.Code != http.StatusNoContent || !called {
		t.Fatalf("expected authorized call, code=%d called=%v body=%s", res.Code, called, res.Body.String())
	}
}

func TestRequireAuthRejectsCookieWithoutCSRF(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	token, _, err := security.SignJWT(privateKey, "usr_1", models.RolePatient, "access", time.Minute)
	if err != nil {
		t.Fatalf("SignJWT returned error: %v", err)
	}
	middleware := New(&privateKey.PublicKey, fakeAuthzStore{user: models.User{ID: "usr_1", Role: models.RolePatient}})
	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	res := httptest.NewRecorder()

	middleware.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run")
	})).ServeHTTP(res, req)

	if res.Code != http.StatusForbidden {
		t.Fatalf("expected csrf rejection, got %d", res.Code)
	}
}

func TestRequireAuthRejectsCookieGETWithoutCSRF(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	token, _, err := security.SignJWT(privateKey, "usr_1", models.RolePatient, "access", time.Minute)
	if err != nil {
		t.Fatalf("SignJWT returned error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	res := httptest.NewRecorder()

	New(&privateKey.PublicKey, fakeAuthzStore{user: models.User{ID: "usr_1", Role: models.RolePatient}}).
		RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not run")
		})).ServeHTTP(res, req)

	if res.Code != http.StatusForbidden {
		t.Fatalf("expected csrf rejection, got %d", res.Code)
	}
}

func TestRequireAuthAcceptsCookieWithCSRF(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	token, _, err := security.SignJWT(privateKey, "usr_1", models.RolePatient, "access", time.Minute)
	if err != nil {
		t.Fatalf("SignJWT returned error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf"})
	req.Header.Set("X-CSRF-Token", "csrf")
	res := httptest.NewRecorder()

	New(&privateKey.PublicKey, fakeAuthzStore{user: models.User{ID: "usr_1", Role: models.RolePatient}}).
		RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(res, req)

	if res.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", res.Code)
	}
}

func TestRequireAuthRejectsRefreshTokenKind(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	token, _, err := security.SignJWT(privateKey, "usr_1", models.RolePatient, "refresh", time.Minute)
	if err != nil {
		t.Fatalf("SignJWT returned error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()

	New(&privateKey.PublicKey, fakeAuthzStore{user: models.User{ID: "usr_1", Role: models.RolePatient}}).
		RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not run")
		})).ServeHTTP(res, req)

	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.Code)
	}
}

func TestRequireAuthRejectsMissingToken(t *testing.T) {
	t.Parallel()
	res := httptest.NewRecorder()
	New(nil, fakeAuthzStore{}).RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run")
	})).ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/protected", nil))
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.Code)
	}
}

func TestRequireAuthRejectsInvalidVerifierAndToken(t *testing.T) {
	t.Parallel()
	withToken := httptest.NewRequest(http.MethodGet, "/protected", nil)
	withToken.Header.Set("Authorization", "Bearer token")
	nilKeyRes := httptest.NewRecorder()
	New(nil, fakeAuthzStore{}).RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run")
	})).ServeHTTP(nilKeyRes, withToken)
	if nilKeyRes.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for nil verifier, got %d", nilKeyRes.Code)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	invalidTokenReq := httptest.NewRequest(http.MethodGet, "/protected", nil)
	invalidTokenReq.Header.Set("Authorization", "Bearer invalid")
	invalidTokenRes := httptest.NewRecorder()
	New(&privateKey.PublicKey, fakeAuthzStore{}).RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run")
	})).ServeHTTP(invalidTokenRes, invalidTokenReq)
	if invalidTokenRes.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid token, got %d", invalidTokenRes.Code)
	}
}

func TestAuthorizeDeniedWritesAudit(t *testing.T) {
	t.Parallel()
	var audit models.AuditLog
	middleware := New(nil, fakeAuthzStore{
		user:  models.User{ID: "usr_1", Role: models.RolePatient},
		audit: &audit,
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/patients/usr_2", nil)
	req = req.WithContext(WithClaims(req.Context(), &security.Claims{UserID: "usr_1", Role: models.RolePatient}))
	res := httptest.NewRecorder()

	middleware.Authorize("patients", models.ScopeReadPatient, []string{models.RolePatient}, func(*http.Request) string {
		return "usr_2"
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run")
	})).ServeHTTP(res, req)

	if res.Code != http.StatusForbidden || audit.Allowed {
		t.Fatalf("expected forbidden audited denial, code=%d audit=%#v", res.Code, audit)
	}
}

func TestAuthorizeResolvedCaregiverAndMissingResource(t *testing.T) {
	t.Parallel()
	var audit models.AuditLog
	middleware := New(nil, fakeAuthzStore{
		user:         models.User{ID: "cg_1", Role: models.RoleCaregiver},
		relationship: true,
		consent:      true,
		audit:        &audit,
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/alerts/alrt_1", nil)
	req = req.WithContext(WithClaims(req.Context(), &security.Claims{UserID: "cg_1", Role: models.RoleCaregiver}))
	res := httptest.NewRecorder()
	called := false

	middleware.AuthorizeResolved("health_alerts", models.ScopeReadAlerts, []string{models.RoleCaregiver}, func(*http.Request) (string, error) {
		return "usr_1", nil
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(res, req)

	if res.Code != http.StatusNoContent || !called || !audit.Allowed {
		t.Fatalf("expected resolved caregiver access, code=%d called=%v audit=%#v", res.Code, called, audit)
	}

	missingReq := httptest.NewRequest(http.MethodGet, "/v1/alerts/missing", nil)
	missingReq = missingReq.WithContext(WithClaims(missingReq.Context(), &security.Claims{UserID: "cg_1", Role: models.RoleCaregiver}))
	missingRes := httptest.NewRecorder()
	middleware.AuthorizeResolved("health_alerts", models.ScopeReadAlerts, []string{models.RoleCaregiver}, func(*http.Request) (string, error) {
		return "", store.ErrNotFound
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run for missing resource")
	})).ServeHTTP(missingRes, missingReq)

	if missingRes.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing resolved resource, got %d", missingRes.Code)
	}
}
