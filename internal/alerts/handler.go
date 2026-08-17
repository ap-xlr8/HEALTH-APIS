package alerts

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"healthos/backend/internal/authz"
	"healthos/backend/internal/models"
	"healthos/backend/internal/store"
	"healthos/backend/pkg/httpx"
)

type Store interface {
	FindAlertByID(ctx context.Context, id string) (models.Alert, error)
	AcknowledgeAlert(ctx context.Context, id string) (models.Alert, error)
	CreateAlert(ctx context.Context, alert models.Alert) error
	ListAlerts(ctx context.Context, patientID string) ([]models.Alert, error)
}

type Broadcaster interface {
	Broadcast(payload any)
}

type Handler struct {
	store       Store
	broadcaster Broadcaster
}

func New(store Store, broadcaster ...Broadcaster) Handler {
	var b Broadcaster
	if len(broadcaster) > 0 {
		b = broadcaster[0]
	}
	return Handler{store: store, broadcaster: b}
}

type sosLocationRequest struct {
	Lat float64 `json:"lat"`
	Lng float64 `json:"lng"`
}

type triggerSosRequest struct {
	Location sosLocationRequest `json:"location"`
	Trigger  string             `json:"trigger"`
}

func (h Handler) TriggerSOS(w http.ResponseWriter, r *http.Request) {
	claims, ok := authz.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	var req triggerSosRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Trigger == "" {
		req.Trigger = "MANUAL_BUTTON"
	}

	msg := "Alerta SOS de emergencia activada por el paciente"
	if req.Location.Lat != 0 || req.Location.Lng != 0 {
		msg = fmt.Sprintf("Alerta SOS de emergencia en coordenadas (Lat: %.5f, Lng: %.5f)", req.Location.Lat, req.Location.Lng)
	}

	alert := models.Alert{
		ID:           "alrt_" + uuid.NewString(),
		PatientID:    claims.UserID,
		Type:         "sos_emergency",
		Severity:     "critical",
		Message:      msg,
		Acknowledged: false,
		CreatedAt:    time.Now().UTC(),
	}

	if err := h.store.CreateAlert(r.Context(), alert); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to trigger sos alert")
		return
	}

	if h.broadcaster != nil {
		h.broadcaster.Broadcast(map[string]any{
			"type":        "alert.created",
			"alertId":     alert.ID,
			"patientId":   alert.PatientID,
			"level":       5,
			"metric":      "sos",
			"location":    map[string]float64{"lat": req.Location.Lat, "lng": req.Location.Lng},
			"triggeredAt": alert.CreatedAt,
		})
		h.broadcaster.Broadcast(map[string]any{
			"type":      "health.event.critical",
			"patientId": alert.PatientID,
			"metric":    "sos",
			"value":     1.0,
			"location":  map[string]float64{"lat": req.Location.Lat, "lng": req.Location.Lng},
		})
	}

	httpx.WriteJSON(w, http.StatusCreated, alert)
}

func (h Handler) GetAlert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || len(id) > 80 {
		httpx.WriteError(w, http.StatusBadRequest, "alert id is required")
		return
	}
	alert, err := h.store.FindAlertByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "alert not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "alert lookup failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, alert)
}

func (h Handler) Acknowledge(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || len(id) > 80 {
		httpx.WriteError(w, http.StatusBadRequest, "alert id is required")
		return
	}
	alert, err := h.store.AcknowledgeAlert(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "alert not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "alert update failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, alert)
}

func (h Handler) List(w http.ResponseWriter, r *http.Request) {
	patientID := r.URL.Query().Get("patientId")
	if patientID == "" {
		patientID = r.URL.Query().Get("patient_id")
	}
	if claims, ok := authz.ClaimsFromContext(r.Context()); ok && claims != nil {
		if claims.Role == models.RolePatient || patientID == "" {
			patientID = claims.UserID
		}
	}
	alerts, err := h.store.ListAlerts(r.Context(), patientID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to list alerts")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, alerts)
}
