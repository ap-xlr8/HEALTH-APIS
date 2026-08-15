package alerts

import (
	"context"
	"errors"
	"net/http"

	"healthos/backend/internal/models"
	"healthos/backend/internal/store"
	"healthos/backend/pkg/httpx"
)

type Store interface {
	FindAlertByID(ctx context.Context, id string) (models.Alert, error)
	AcknowledgeAlert(ctx context.Context, id string) (models.Alert, error)
}

type Handler struct {
	store Store
}

func New(store Store) Handler {
	return Handler{store: store}
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
