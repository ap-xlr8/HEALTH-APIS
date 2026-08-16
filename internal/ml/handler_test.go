package ml

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"healthos/backend/internal/models"
)

type mockStore struct {
	user         models.User
	measurements []models.Measurement
	driftEvents  []models.MLDriftEvent
}

func (m *mockStore) FindUserByID(ctx context.Context, id string) (models.User, error) {
	return m.user, nil
}

func (m *mockStore) ListMeasurements(ctx context.Context, filter models.MeasurementFilter) ([]models.Measurement, error) {
	return m.measurements, nil
}

func (m *mockStore) RecordMLDriftEvent(ctx context.Context, event models.MLDriftEvent) error {
	m.driftEvents = append(m.driftEvents, event)
	return nil
}

func (m *mockStore) GetLatestMLDriftEvent(ctx context.Context, modelName string) (models.MLDriftEvent, error) {
	if len(m.driftEvents) > 0 {
		return m.driftEvents[len(m.driftEvents)-1], nil
	}
	return models.MLDriftEvent{}, nil
}

func TestGetRiskAssessment_Success(t *testing.T) {
	store := &mockStore{
		user: models.User{ID: "pat_1"},
		measurements: []models.Measurement{
			{Type: "heart_rate", Value: 75.0, Timestamp: time.Now().UTC()},
			{Type: "blood_oxygen", Value: 98.0, Timestamp: time.Now().UTC()},
		},
	}
	h := NewHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/v1/patients/pat_1/risk-assessment", nil)
	req.SetPathValue("id", "pat_1")
	w := httptest.NewRecorder()

	h.GetRiskAssessment(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetBiometricEstimations_Success(t *testing.T) {
	store := &mockStore{
		user: models.User{
			ID: "pat_1",
			HealthProfile: &models.HealthProfile{
				WeightKg: 75,
				HeightCm: 180,
			},
		},
		measurements: []models.Measurement{
			{Type: "heart_rate", Value: 70.0, Timestamp: time.Now().UTC()},
			{Type: "blood_oxygen", Value: 99.0, Timestamp: time.Now().UTC()},
			{Type: "eda", Value: 3.5, Timestamp: time.Now().UTC()},
		},
	}
	h := NewHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/v1/patients/pat_1/biometric-estimations", nil)
	req.SetPathValue("id", "pat_1")
	w := httptest.NewRecorder()

	h.GetBiometricEstimations(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDriftWebhook_Success(t *testing.T) {
	store := &mockStore{}
	h := NewHandler(store)

	body, _ := json.Marshal(map[string]any{
		"model_name":          "risk_score",
		"metric":              "psi",
		"current_drift_score": 0.28,
		"threshold":           0.25,
		"action":              "pause",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/ml/drift-webhook", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.DriftWebhook(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(store.driftEvents) != 1 {
		t.Fatalf("expected 1 drift event recorded, got %d", len(store.driftEvents))
	}
	if store.driftEvents[0].Status != "model_paused" {
		t.Fatalf("expected model_paused status, got %s", store.driftEvents[0].Status)
	}

	// Resume model
	Default().SetModelPaused("risk_score", false)
}
