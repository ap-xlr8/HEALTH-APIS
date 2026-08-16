package alerts

import (
	"context"
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

type fakeAlertStore struct {
	alert models.Alert
}

func (f *fakeAlertStore) FindAlertByID(ctx context.Context, id string) (models.Alert, error) {
	if f.alert.ID == id {
		return f.alert, nil
	}
	return models.Alert{}, store.ErrNotFound
}

func (f *fakeAlertStore) AcknowledgeAlert(ctx context.Context, id string) (models.Alert, error) {
	if f.alert.ID == id {
		f.alert.Acknowledged = true
		return f.alert, nil
	}
	return models.Alert{}, store.ErrNotFound
}

func (f *fakeAlertStore) CreateAlert(ctx context.Context, alert models.Alert) error {
	f.alert = alert
	return nil
}

func TestGetAlert(t *testing.T) {
	t.Parallel()
	store := &fakeAlertStore{
		alert: models.Alert{ID: "alrt_1", PatientID: "usr_1", Type: "tachycardia", Severity: "critical", CreatedAt: time.Now().UTC()},
	}
	handler := New(store)
	req := httptest.NewRequest(http.MethodGet, "/v1/alerts/alrt_1", nil)
	req.SetPathValue("id", "alrt_1")
	res := httptest.NewRecorder()

	handler.GetAlert(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", res.Code, res.Body.String())
	}
}

func TestGetAlertNotFound(t *testing.T) {
	t.Parallel()
	handler := New(&fakeAlertStore{})
	req := httptest.NewRequest(http.MethodGet, "/v1/alerts/missing", nil)
	req.SetPathValue("id", "missing")
	res := httptest.NewRecorder()

	handler.GetAlert(res, req)

	if res.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", res.Code)
	}
}

func TestGetAlertRejectsInvalidID(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/v1/alerts/", nil)
	res := httptest.NewRecorder()

	New(&fakeAlertStore{}).GetAlert(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", res.Code)
	}
}

func TestAcknowledgeAlert(t *testing.T) {
	t.Parallel()
	handler := New(&fakeAlertStore{
		alert: models.Alert{ID: "alrt_1", PatientID: "usr_1", Type: "tachycardia", Severity: "critical", CreatedAt: time.Now().UTC()},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/alerts/alrt_1/acknowledge", nil)
	req.SetPathValue("id", "alrt_1")
	res := httptest.NewRecorder()

	handler.Acknowledge(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", res.Code, res.Body.String())
	}
}

func TestAcknowledgeAlertRejectsInvalidAndMissing(t *testing.T) {
	t.Parallel()
	handler := New(&fakeAlertStore{})

	invalid := httptest.NewRequest(http.MethodPost, "/v1/alerts//acknowledge", nil)
	invalidRes := httptest.NewRecorder()
	handler.Acknowledge(invalidRes, invalid)
	if invalidRes.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", invalidRes.Code)
	}

	missing := httptest.NewRequest(http.MethodPost, "/v1/alerts/missing/acknowledge", nil)
	missing.SetPathValue("id", "missing")
	missingRes := httptest.NewRecorder()
	handler.Acknowledge(missingRes, missing)
	if missingRes.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", missingRes.Code)
	}
}

type recordingBroadcaster struct {
	payloads []map[string]any
}

func (r *recordingBroadcaster) Broadcast(payload any) {
	r.payloads = append(r.payloads, payload.(map[string]any))
}

func authenticatedRequest(method, target string, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req.WithContext(authz.WithClaims(req.Context(), &security.Claims{UserID: "usr_sos", Role: models.RolePatient}))
}

func TestTriggerSOSWithLocation(t *testing.T) {
	t.Parallel()
	broadcaster := &recordingBroadcaster{}
	handler := New(&fakeAlertStore{}, broadcaster)

	req := authenticatedRequest(http.MethodPost, "/v1/alerts/sos", `{"location":{"lat":19.4326,"lng":-99.1332},"trigger":"WRIST_BUTTON"}`)
	res := httptest.NewRecorder()
	handler.TriggerSOS(res, req)

	if res.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "coordenadas") {
		t.Fatalf("expected coordinates message, got %s", res.Body.String())
	}
	if len(broadcaster.payloads) != 2 {
		t.Fatalf("expected 2 broadcasts, got %d", len(broadcaster.payloads))
	}
	if broadcaster.payloads[0]["type"] != "alert.created" || broadcaster.payloads[1]["type"] != "health.event.critical" {
		t.Fatalf("unexpected broadcast types: %v", broadcaster.payloads)
	}
}

func TestTriggerSOSDefaultTrigger(t *testing.T) {
	t.Parallel()
	handler := New(&fakeAlertStore{}, &recordingBroadcaster{})

	req := authenticatedRequest(http.MethodPost, "/v1/alerts/sos", `{}`)
	res := httptest.NewRecorder()
	handler.TriggerSOS(res, req)

	if res.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "activada por el paciente") {
		t.Fatalf("expected default message, got %s", res.Body.String())
	}
}

func TestTriggerSOSUnauthenticated(t *testing.T) {
	t.Parallel()
	handler := New(&fakeAlertStore{}, &recordingBroadcaster{})

	req := httptest.NewRequest(http.MethodPost, "/v1/alerts/sos", strings.NewReader(`{}`))
	res := httptest.NewRecorder()
	handler.TriggerSOS(res, req)

	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.Code)
	}
}

func TestGetAlertInternalError(t *testing.T) {
	t.Parallel()
	failing := &erroringAlertStore{}
	handler := New(failing)
	req := httptest.NewRequest(http.MethodGet, "/v1/alerts/alrt_1", nil)
	req.SetPathValue("id", "alrt_1")
	res := httptest.NewRecorder()
	handler.GetAlert(res, req)
	if res.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", res.Code)
	}
}

type erroringAlertStore struct {
	fakeAlertStore
}

func (f *erroringAlertStore) FindAlertByID(ctx context.Context, id string) (models.Alert, error) {
	return models.Alert{}, context.DeadlineExceeded
}
