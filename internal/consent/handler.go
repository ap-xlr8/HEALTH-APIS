package consent

import (
	"context"
	"net/http"

	"healthos/backend/internal/authz"
	"healthos/backend/internal/models"
	"healthos/backend/pkg/httpx"
)

type HandlerStore interface {
	UpsertConsent(ctx context.Context, consent models.Consent) error
}

type Handler struct {
	store       HandlerStore
	broadcaster Broadcaster
}

func NewHandler(store HandlerStore, broadcaster Broadcaster) Handler {
	return Handler{store: store, broadcaster: broadcaster}
}

func (h Handler) Grant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CaregiverID string   `json:"caregiver_id"`
		Scopes      []string `json:"scopes"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	claims, _ := authz.ClaimsFromContext(r.Context())
	consent, err := New(h.store, h.broadcaster).Grant(r.Context(), claims.UserID, req.CaregiverID, req.Scopes)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"status": "success", "data": consent})
}

func (h Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	claims, _ := authz.ClaimsFromContext(r.Context())
	consent, err := New(h.store, h.broadcaster).Revoke(r.Context(), claims.UserID, r.PathValue("caregiver_id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "data": consent})
}
