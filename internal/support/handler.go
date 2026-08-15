package support

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"healthos/backend/internal/authz"
	"healthos/backend/internal/models"
	"healthos/backend/pkg/httpx"
)

type Store interface {
	CreateSupportTicket(ctx context.Context, ticket models.SupportTicket) error
	ListSupportTickets(ctx context.Context, userID string) ([]models.SupportTicket, error)
}

type Handler struct {
	store Store
}

func New(store Store) Handler {
	return Handler{store: store}
}

func (h Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Subject string `json:"subject"`
		Body    string `json:"body"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	subject, body := strings.TrimSpace(req.Subject), strings.TrimSpace(req.Body)
	if subject == "" || len(subject) > 160 || body == "" || len(body) > 4000 {
		httpx.WriteError(w, http.StatusBadRequest, "subject and body are required")
		return
	}
	id := randomID()
	if id == "" {
		httpx.WriteError(w, http.StatusInternalServerError, "secure id generation failed")
		return
	}
	claims, _ := authz.ClaimsFromContext(r.Context())
	now := time.Now().UTC()
	ticket := models.SupportTicket{
		ID:        "sup_" + id,
		UserID:    claims.UserID,
		Status:    "open",
		Subject:   subject,
		Body:      body,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := h.store.CreateSupportTicket(r.Context(), ticket); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create support ticket")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"status": "success", "data": ticket})
}

func (h Handler) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := authz.ClaimsFromContext(r.Context())
	tickets, err := h.store.ListSupportTickets(r.Context(), claims.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list support tickets")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "data": tickets})
}

func randomID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
