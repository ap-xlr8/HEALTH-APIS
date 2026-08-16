package notifications

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
	CreateNotification(ctx context.Context, notification models.Notification) error
	ListNotifications(ctx context.Context, userID string) ([]models.Notification, error)
	GetNotificationPreferences(ctx context.Context, userID string) (models.NotificationPreferences, error)
	UpdateNotificationPreferences(ctx context.Context, userID string, prefs models.NotificationPreferences) error
}

type Handler struct {
	store Store
}

func New(store Store) Handler {
	return Handler{store: store}
}

func (h Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Channel  string         `json:"channel"`
		Title    string         `json:"title"`
		Body     string         `json:"body"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	channel, title, body := strings.TrimSpace(req.Channel), strings.TrimSpace(req.Title), strings.TrimSpace(req.Body)
	if !allowed(channel, "push", "email", "sms") || title == "" || len(title) > 120 || body == "" || len(body) > 1000 {
		httpx.WriteError(w, http.StatusBadRequest, "valid channel, title and body are required")
		return
	}
	id := randomID()
	if id == "" {
		httpx.WriteError(w, http.StatusInternalServerError, "secure id generation failed")
		return
	}
	claims, _ := authz.ClaimsFromContext(r.Context())
	notification := models.Notification{
		ID:        "not_" + id,
		UserID:    claims.UserID,
		Channel:   channel,
		Title:     title,
		Body:      body,
		Metadata:  req.Metadata,
		CreatedAt: time.Now().UTC(),
	}
	if err := h.store.CreateNotification(r.Context(), notification); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create notification")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"status": "success", "data": notification})
}

func (h Handler) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := authz.ClaimsFromContext(r.Context())
	notifications, err := h.store.ListNotifications(r.Context(), claims.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list notifications")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "data": notifications})
}

func (h Handler) GetPreferences(w http.ResponseWriter, r *http.Request) {
	claims, ok := authz.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	prefs, err := h.store.GetNotificationPreferences(r.Context(), claims.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to load notification preferences")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"data":   prefs,
	})
}

func (h Handler) UpdatePreferences(w http.ResponseWriter, r *http.Request) {
	claims, ok := authz.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	var req models.NotificationPreferences
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.AlertTypes == nil {
		req.AlertTypes = map[string]bool{
			"tachycardia":         true,
			"hypoxemia":           true,
			"sos":                 true,
			"medication_reminder": true,
			"device_status":       true,
		}
	}
	if err := h.store.UpdateNotificationPreferences(r.Context(), claims.UserID, req); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to update notification preferences")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"message": "notification preferences updated successfully",
		"data":    req,
	})
}

func allowed(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}

func randomID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
