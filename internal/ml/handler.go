package ml

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"healthos/backend/internal/models"
	"healthos/backend/internal/store"
	"healthos/backend/pkg/httpx"
)

type Store interface {
	FindUserByID(ctx context.Context, id string) (models.User, error)
	ListMeasurements(ctx context.Context, filter models.MeasurementFilter) ([]models.Measurement, error)
	RecordMLDriftEvent(ctx context.Context, event models.MLDriftEvent) error
	GetLatestMLDriftEvent(ctx context.Context, modelName string) (models.MLDriftEvent, error)
}

type Handler struct {
	store  Store
	engine *InferenceEngine
}

func NewHandler(store Store) Handler {
	return Handler{
		store:  store,
		engine: Default(),
	}
}

func (h Handler) GetRiskAssessment(w http.ResponseWriter, r *http.Request) {
	patientID := strings.TrimSpace(r.PathValue("id"))
	if patientID == "" || len(patientID) > 80 {
		httpx.WriteError(w, http.StatusBadRequest, "patient id is required")
		return
	}

	// Fetch recent measurements for the patient (last 100)
	measurements, err := h.store.ListMeasurements(r.Context(), models.MeasurementFilter{
		PatientID: patientID,
		Limit:     100,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to query patient measurements")
		return
	}

	if len(measurements) == 0 {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"status": "success",
			"data": RiskResult{
				RiskScore:         5.0,
				RiskLevel:         "LOW",
				IsAnomalyDetected: false,
				Confidence:        0.70,
				EvaluatedAt:       time.Now().UTC(),
				Factors:           []string{"insufficient_recent_data"},
			},
		})
		return
	}

	riskResult, err := h.engine.EvaluateMeasurements(measurements)
	if err != nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"data":   riskResult,
	})
}

func (h Handler) GetBiometricEstimations(w http.ResponseWriter, r *http.Request) {
	patientID := strings.TrimSpace(r.PathValue("id"))
	if patientID == "" || len(patientID) > 80 {
		httpx.WriteError(w, http.StatusBadRequest, "patient id is required")
		return
	}

	user, err := h.store.FindUserByID(r.Context(), patientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "patient not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "failed to retrieve patient profile")
		return
	}

	measurements, err := h.store.ListMeasurements(r.Context(), models.MeasurementFilter{
		PatientID: patientID,
		Limit:     100,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to query patient measurements")
		return
	}

	if len(measurements) == 0 {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"status": "success",
			"data":   nil,
		})
		return
	}

	estimations := h.engine.ComputeBiometricEstimations(patientID, user.HealthProfile, measurements)

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"data":   estimations,
	})
}

type driftWebhookRequest struct {
	ModelName         string  `json:"model_name"`
	Metric            string  `json:"metric"`
	CurrentDriftScore float64 `json:"current_drift_score"`
	Threshold         float64 `json:"threshold"`
	Action            string  `json:"action"` // pause, resume, notify
}

func (h Handler) DriftWebhook(w http.ResponseWriter, r *http.Request) {
	var req driftWebhookRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	modelName := strings.TrimSpace(req.ModelName)
	if modelName == "" {
		httpx.WriteError(w, http.StatusBadRequest, "model_name is required")
		return
	}

	now := time.Now().UTC()
	status := "drift_detected"
	if req.Action == "pause" || req.CurrentDriftScore > req.Threshold {
		h.engine.SetModelPaused(modelName, true)
		status = "model_paused"
	} else if req.Action == "resume" {
		h.engine.SetModelPaused(modelName, false)
		status = "model_active"
	}

	driftEvent := models.MLDriftEvent{
		ID:                "drf_" + uuid.NewString(),
		ModelName:         modelName,
		Metric:            req.Metric,
		CurrentDriftScore: req.CurrentDriftScore,
		Threshold:         req.Threshold,
		Status:            status,
		TriggeredAt:       now,
		CreatedAt:         now,
	}

	_ = h.store.RecordMLDriftEvent(r.Context(), driftEvent)

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"message": "drift event processed",
		"data":    driftEvent,
	})
}
