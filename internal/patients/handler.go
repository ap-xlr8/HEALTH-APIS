package patients

import (
	"context"
	"errors"
	"net/http"

	"healthos/backend/internal/models"
	"healthos/backend/internal/store"
	"healthos/backend/pkg/httpx"
)

type Store interface {
	FindUserByID(ctx context.Context, id string) (models.User, error)
}

type Handler struct {
	store Store
}

func New(store Store) Handler {
	return Handler{store: store}
}

func (h Handler) GetPatient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || len(id) > 80 {
		httpx.WriteError(w, http.StatusBadRequest, "patient id is required")
		return
	}
	user, err := h.store.FindUserByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "patient not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "patient lookup failed")
		return
	}
	if user.Role != models.RolePatient {
		httpx.WriteError(w, http.StatusNotFound, "patient not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id":                user.ID,
		"first_name":        user.FirstName,
		"last_name":         user.LastName,
		"age":               user.Age,
		"health_profile":    user.HealthProfile,
		"active_conditions": user.ActiveConditions,
	})
}
