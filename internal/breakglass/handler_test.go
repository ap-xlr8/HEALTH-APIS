package breakglass

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"healthos/backend/internal/authz"
	"healthos/backend/internal/models"
	"healthos/backend/internal/store"
	"healthos/backend/pkg/security"
)

type fakeStore struct {
	requests   map[string]models.BreakGlassRequest
	audits     []models.AuditLog
	createErr  error
	lookupErr  error
	approveErr error
}

func newFakeStore() *fakeStore {
	return &fakeStore{requests: map[string]models.BreakGlassRequest{}}
}

func (f *fakeStore) CreateBreakGlassRequest(ctx context.Context, request models.BreakGlassRequest) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.requests[request.ID] = request
	return nil
}

func (f *fakeStore) FindBreakGlassRequestByID(ctx context.Context, id string) (models.BreakGlassRequest, error) {
	if f.lookupErr != nil {
		return models.BreakGlassRequest{}, f.lookupErr
	}
	request, ok := f.requests[id]
	if !ok {
		return models.BreakGlassRequest{}, store.ErrNotFound
	}
	return request, nil
}

func (f *fakeStore) ApproveBreakGlassRequest(ctx context.Context, id, approverID string, approvedAt time.Time) (models.BreakGlassRequest, error) {
	if f.approveErr != nil {
		return models.BreakGlassRequest{}, f.approveErr
	}
	request, ok := f.requests[id]
	if !ok || request.RequesterID == approverID || request.Status != "pending" || approvedAt.After(request.ExpiresAt) {
		return models.BreakGlassRequest{}, store.ErrNotFound
	}
	request.Status = "approved"
	request.ApproverID = approverID
	request.ApprovedAt = approvedAt
	f.requests[id] = request
	return request, nil
}

func (f *fakeStore) WriteAudit(ctx context.Context, log models.AuditLog) error {
	f.audits = append(f.audits, log)
	return nil
}

func TestRequestBreakGlass(t *testing.T) {
	t.Parallel()
	fake := newFakeStore()
	handler := New(fake)
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/break-glass/request", strings.NewReader(`{"reason":"incident response","duration_minutes":120}`))
	req = req.WithContext(authz.WithClaims(req.Context(), &security.Claims{UserID: "admin_1", Role: models.RoleAdmin}))
	res := httptest.NewRecorder()

	handler.Request(res, req)

	if res.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", res.Code, res.Body.String())
	}
	if len(fake.requests) != 1 || len(fake.audits) != 1 {
		t.Fatalf("expected one request and one audit, requests=%d audits=%d", len(fake.requests), len(fake.audits))
	}
}

func TestRequestBreakGlassRejectsInvalidDuration(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/break-glass/request", strings.NewReader(`{"reason":"incident","duration_minutes":121}`))
	req = req.WithContext(authz.WithClaims(req.Context(), &security.Claims{UserID: "admin_1", Role: models.RoleAdmin}))
	res := httptest.NewRecorder()

	New(newFakeStore()).Request(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", res.Code)
	}
}

func TestRequestBreakGlassRejectsUnauthorizedBadJSONAndPersistence(t *testing.T) {
	t.Parallel()
	unauthorized := httptest.NewRequest(http.MethodPost, "/v1/admin/break-glass/request", strings.NewReader(`{}`))
	unauthorized = unauthorized.WithContext(authz.WithClaims(unauthorized.Context(), &security.Claims{UserID: "usr_1", Role: models.RolePatient}))
	unauthorizedRes := httptest.NewRecorder()
	New(newFakeStore()).Request(unauthorizedRes, unauthorized)
	if unauthorizedRes.Code != http.StatusForbidden {
		t.Fatalf("expected unauthorized 403, got %d", unauthorizedRes.Code)
	}

	badJSON := httptest.NewRequest(http.MethodPost, "/v1/admin/break-glass/request", strings.NewReader(`{`))
	badJSON = badJSON.WithContext(authz.WithClaims(badJSON.Context(), &security.Claims{UserID: "admin_1", Role: models.RoleAdmin}))
	badJSONRes := httptest.NewRecorder()
	New(newFakeStore()).Request(badJSONRes, badJSON)
	if badJSONRes.Code != http.StatusBadRequest {
		t.Fatalf("expected bad json 400, got %d", badJSONRes.Code)
	}

	persistence := httptest.NewRequest(http.MethodPost, "/v1/admin/break-glass/request", strings.NewReader(`{"reason":"incident","duration_minutes":60}`))
	persistence = persistence.WithContext(authz.WithClaims(persistence.Context(), &security.Claims{UserID: "admin_1", Role: models.RoleAdmin}))
	persistenceRes := httptest.NewRecorder()
	New(&fakeStore{requests: map[string]models.BreakGlassRequest{}, createErr: errors.New("db down")}).Request(persistenceRes, persistence)
	if persistenceRes.Code != http.StatusInternalServerError {
		t.Fatalf("expected persistence 500, got %d", persistenceRes.Code)
	}
}

func TestApproveBreakGlass(t *testing.T) {
	t.Parallel()
	fake := newFakeStore()
	request := models.BreakGlassRequest{
		ID:          "bgr_1",
		RequesterID: "admin_1",
		Reason:      "incident",
		Status:      "pending",
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
		CreatedAt:   time.Now().UTC(),
	}
	fake.requests[request.ID] = request
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/break-glass/bgr_1/approve", nil)
	req.SetPathValue("id", request.ID)
	req = req.WithContext(authz.WithClaims(req.Context(), &security.Claims{UserID: "admin_2", Role: models.RoleAdmin}))
	res := httptest.NewRecorder()

	New(fake).Approve(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", res.Code, res.Body.String())
	}
	if fake.requests[request.ID].ApproverID != "admin_2" {
		t.Fatalf("expected admin_2 approval, got %#v", fake.requests[request.ID])
	}
}

func TestApproveBreakGlassEnforcesTwoPersonRule(t *testing.T) {
	t.Parallel()
	fake := newFakeStore()
	fake.requests["bgr_1"] = models.BreakGlassRequest{
		ID:          "bgr_1",
		RequesterID: "admin_1",
		Reason:      "incident",
		Status:      "pending",
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
		CreatedAt:   time.Now().UTC(),
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/break-glass/bgr_1/approve", nil)
	req.SetPathValue("id", "bgr_1")
	req = req.WithContext(authz.WithClaims(req.Context(), &security.Claims{UserID: "admin_1", Role: models.RoleAdmin}))
	res := httptest.NewRecorder()

	New(fake).Approve(res, req)

	if res.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", res.Code)
	}
}

func TestApproveBreakGlassRejectsNotFoundExpiredAndPersistence(t *testing.T) {
	t.Parallel()
	notFound := httptest.NewRequest(http.MethodPost, "/v1/admin/break-glass/missing/approve", nil)
	notFound.SetPathValue("id", "missing")
	notFound = notFound.WithContext(authz.WithClaims(notFound.Context(), &security.Claims{UserID: "admin_2", Role: models.RoleAdmin}))
	notFoundRes := httptest.NewRecorder()
	New(newFakeStore()).Approve(notFoundRes, notFound)
	if notFoundRes.Code != http.StatusNotFound {
		t.Fatalf("expected not found 404, got %d", notFoundRes.Code)
	}

	expiredStore := newFakeStore()
	expiredStore.requests["bgr_1"] = models.BreakGlassRequest{ID: "bgr_1", RequesterID: "admin_1", Status: "pending", ExpiresAt: time.Now().UTC().Add(-time.Minute)}
	expired := httptest.NewRequest(http.MethodPost, "/v1/admin/break-glass/bgr_1/approve", nil)
	expired.SetPathValue("id", "bgr_1")
	expired = expired.WithContext(authz.WithClaims(expired.Context(), &security.Claims{UserID: "admin_2", Role: models.RoleAdmin}))
	expiredRes := httptest.NewRecorder()
	New(expiredStore).Approve(expiredRes, expired)
	if expiredRes.Code != http.StatusConflict {
		t.Fatalf("expected expired 409, got %d", expiredRes.Code)
	}

	lookupStore := newFakeStore()
	lookupStore.lookupErr = errors.New("lookup failed")
	lookup := httptest.NewRequest(http.MethodPost, "/v1/admin/break-glass/bgr_1/approve", nil)
	lookup.SetPathValue("id", "bgr_1")
	lookup = lookup.WithContext(authz.WithClaims(lookup.Context(), &security.Claims{UserID: "admin_2", Role: models.RoleAdmin}))
	lookupRes := httptest.NewRecorder()
	New(lookupStore).Approve(lookupRes, lookup)
	if lookupRes.Code != http.StatusInternalServerError {
		t.Fatalf("expected lookup 500, got %d", lookupRes.Code)
	}

	approveStore := newFakeStore()
	approveStore.requests["bgr_1"] = models.BreakGlassRequest{ID: "bgr_1", RequesterID: "admin_1", Status: "pending", ExpiresAt: time.Now().UTC().Add(time.Hour)}
	approveStore.approveErr = errors.New("approve failed")
	approve := httptest.NewRequest(http.MethodPost, "/v1/admin/break-glass/bgr_1/approve", nil)
	approve.SetPathValue("id", "bgr_1")
	approve = approve.WithContext(authz.WithClaims(approve.Context(), &security.Claims{UserID: "admin_2", Role: models.RoleAdmin}))
	approveRes := httptest.NewRecorder()
	New(approveStore).Approve(approveRes, approve)
	if approveRes.Code != http.StatusInternalServerError {
		t.Fatalf("expected approve 500, got %d", approveRes.Code)
	}
}
