package alerts

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"healthos/backend/internal/models"
	"healthos/backend/internal/store"
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
