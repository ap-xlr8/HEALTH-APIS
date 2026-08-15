package health

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"healthos/backend/internal/authz"
	"healthos/backend/internal/ml"
	"healthos/backend/internal/models"
	"healthos/backend/pkg/httpx"
)

type Store interface {
	InsertMeasurements(ctx context.Context, measurements []models.Measurement) error
	ListMeasurements(ctx context.Context, filter models.MeasurementFilter) ([]models.Measurement, error)
	CreateAlert(ctx context.Context, alert models.Alert) error
	CreateNotification(ctx context.Context, notification models.Notification) error
}

type Broadcaster interface {
	Broadcast(payload any)
}

type Handler struct {
	store       Store
	broadcaster Broadcaster
}

func New(store Store, broadcaster Broadcaster) Handler {
	return Handler{store: store, broadcaster: broadcaster}
}

type syncRequest struct {
	DeviceID string             `json:"device_id"`
	Data     []measurementInput `json:"data"`
}

type measurementInput struct {
	Type      string  `json:"type"`
	Value     float64 `json:"value"`
	Unit      string  `json:"unit"`
	Timestamp string  `json:"timestamp"`
}

func (h Handler) SyncMeasurements(w http.ResponseWriter, r *http.Request) {
	claims, ok := authz.ClaimsFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "missing authenticated principal")
		return
	}
	if claims.Role != models.RolePatient {
		httpx.WriteError(w, http.StatusForbidden, "only patient mobile clients can sync measurements")
		return
	}
	var req syncRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	measurements, err := validateSync(req, claims.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.store.InsertMeasurements(r.Context(), measurements); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "measurement sync failed")
		return
	}
	alertsTriggered := make([]string, 0)
	for _, measurement := range measurements {
		h.broadcast(map[string]any{
			"type":       "measurement.ingested",
			"patientId":  measurement.PatientID,
			"metric":     measurement.Type,
			"value":      measurement.Value,
			"unit":       measurement.Unit,
			"occurredAt": measurement.Timestamp,
			"eventId":    "evt_" + uuid.NewString(),
		})
		if alert, ok := deriveAlert(measurement); ok {
			if err := h.store.CreateAlert(r.Context(), alert); err == nil {
				h.createAlertNotification(r.Context(), alert, measurement)
				alertsTriggered = append(alertsTriggered, alert.ID)
				h.broadcast(map[string]any{
					"type":        "alert.created",
					"alertId":     alert.ID,
					"patientId":   alert.PatientID,
					"level":       4,
					"metric":      measurement.Type,
					"value":       measurement.Value,
					"triggeredAt": alert.CreatedAt,
				})
				h.broadcast(map[string]any{
					"type":      "health.event.critical",
					"patientId": alert.PatientID,
					"metric":    measurement.Type,
					"value":     measurement.Value,
					"location":  nil,
				})
			}
		}
	}
	// 3. ML Risk and Anomaly Evaluation
	var mlRiskResult *ml.RiskResult
	if evaluatedRisk, err := ml.Default().EvaluateMeasurements(measurements); err == nil {
		mlRiskResult = &evaluatedRisk
	}

	responsePayload := map[string]any{
		"status":           "success",
		"synced_count":     len(measurements),
		"alerts_triggered": alertsTriggered,
	}
	if mlRiskResult != nil {
		responsePayload["ml_risk"] = mlRiskResult
	}

	httpx.WriteJSON(w, http.StatusOK, responsePayload)
}

func (h Handler) createAlertNotification(ctx context.Context, alert models.Alert, measurement models.Measurement) {
	_ = h.store.CreateNotification(ctx, models.Notification{
		ID:      "not_" + uuid.NewString(),
		UserID:  alert.PatientID,
		Channel: "push",
		Title:   "Critical health alert",
		Body:    alert.Message,
		Metadata: map[string]any{
			"alert_id":       alert.ID,
			"measurement_id": measurement.ID,
			"metric":         measurement.Type,
			"value":          measurement.Value,
			"unit":           measurement.Unit,
		},
		CreatedAt: time.Now().UTC(),
	})
}

func (h Handler) ListMeasurements(w http.ResponseWriter, r *http.Request) {
	filter, err := measurementFilterFromRequest(r)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	measurements, err := h.store.ListMeasurements(r.Context(), filter)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "measurement lookup failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "data": measurements})
}

func (h Handler) broadcast(payload any) {
	if h.broadcaster != nil {
		h.broadcaster.Broadcast(payload)
	}
}

func validateSync(req syncRequest, patientID string) ([]models.Measurement, error) {
	if req.DeviceID == "" || len(req.DeviceID) > 80 {
		return nil, errors.New("device_id is required and must be <= 80 characters")
	}
	if len(req.Data) == 0 || len(req.Data) > 1000 {
		return nil, errors.New("data must include between 1 and 1000 measurements")
	}
	expectedUnits := map[string]string{
		"heart_rate":   "bpm",
		"blood_oxygen": "%",
		"steps":        "count",
	}
	measurements := make([]models.Measurement, 0, len(req.Data))
	now := time.Now().UTC()
	for _, input := range req.Data {
		expectedUnit, ok := expectedUnits[input.Type]
		if !ok {
			return nil, errors.New("measurement type must be heart_rate, blood_oxygen, or steps")
		}
		if input.Unit != expectedUnit {
			return nil, errors.New("unit must match measurement type: heart_rate=bpm, blood_oxygen=%, steps=count")
		}
		ts, err := time.Parse(time.RFC3339, input.Timestamp)
		if err != nil {
			return nil, errors.New("timestamp must be ISO8601/RFC3339")
		}
		if ts.After(now.Add(5 * time.Minute)) {
			return nil, errors.New("timestamp cannot be in the future")
		}
		if input.Value < 0 {
			return nil, errors.New("value must be non-negative")
		}
		measurements = append(measurements, models.Measurement{
			ID:        "meas_" + uuid.NewString(),
			PatientID: patientID,
			DeviceID:  req.DeviceID,
			Type:      input.Type,
			Value:     input.Value,
			Unit:      input.Unit,
			Timestamp: ts.UTC(),
			CreatedAt: now,
		})
	}
	return measurements, nil
}

func measurementFilterFromRequest(r *http.Request) (models.MeasurementFilter, error) {
	patientID := r.PathValue("id")
	if patientID == "" || len(patientID) > 80 {
		return models.MeasurementFilter{}, errors.New("patient id is required")
	}
	query := r.URL.Query()
	filter := models.MeasurementFilter{PatientID: patientID, Limit: 100}
	if rawLimit := query.Get("limit"); rawLimit != "" {
		limit, err := strconv.ParseInt(rawLimit, 10, 64)
		if err != nil || limit < 1 || limit > 1000 {
			return models.MeasurementFilter{}, errors.New("limit must be between 1 and 1000")
		}
		filter.Limit = limit
	}
	if metricType := query.Get("type"); metricType != "" {
		switch metricType {
		case "heart_rate", "blood_oxygen", "steps":
			filter.Type = metricType
		default:
			return models.MeasurementFilter{}, errors.New("type must be heart_rate, blood_oxygen, or steps")
		}
	}
	if rawFrom := query.Get("from"); rawFrom != "" {
		from, err := time.Parse(time.RFC3339, rawFrom)
		if err != nil {
			return models.MeasurementFilter{}, errors.New("from must be RFC3339")
		}
		filter.From = from.UTC()
	}
	if rawTo := query.Get("to"); rawTo != "" {
		to, err := time.Parse(time.RFC3339, rawTo)
		if err != nil {
			return models.MeasurementFilter{}, errors.New("to must be RFC3339")
		}
		filter.To = to.UTC()
	}
	if !filter.From.IsZero() && !filter.To.IsZero() && filter.From.After(filter.To) {
		return models.MeasurementFilter{}, errors.New("from must be before to")
	}
	return filter, nil
}

func deriveAlert(measurement models.Measurement) (models.Alert, bool) {
	if measurement.Type == "heart_rate" && measurement.Value >= 140 {
		return models.Alert{
			ID:             "alrt_" + uuid.NewString(),
			PatientID:      measurement.PatientID,
			Type:           "tachycardia",
			Severity:       "critical",
			Message:        "Frecuencia cardiaca anormalmente alta detectada (140 bpm en reposo)",
			MeasurementRef: measurement.ID,
			Acknowledged:   false,
			CreatedAt:      time.Now().UTC(),
		}, true
	}
	if measurement.Type == "blood_oxygen" && measurement.Value < 90 {
		return models.Alert{
			ID:             "alrt_" + uuid.NewString(),
			PatientID:      measurement.PatientID,
			Type:           "hypoxemia",
			Severity:       "critical",
			Message:        "Oxigenacion sanguinea anormalmente baja detectada",
			MeasurementRef: measurement.ID,
			Acknowledged:   false,
			CreatedAt:      time.Now().UTC(),
		}, true
	}
	return models.Alert{}, false
}
