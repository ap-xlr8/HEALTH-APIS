package admin

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"healthos/backend/internal/models"
	"healthos/backend/pkg/httpx"
)

type Store interface {
	ListUsers(ctx context.Context, role, status string, limit int64) ([]models.User, error)
	FindUserByID(ctx context.Context, id string) (models.User, error)
	UpdateUserStatus(ctx context.Context, userID, status string) error
	ListAuditLogs(ctx context.Context, userID, action string, limit int64) ([]models.AuditLog, error)
}

type Handler struct {
	store Store
}

func New(store Store) Handler {
	return Handler{store: store}
}

func (h Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	role := strings.TrimSpace(r.URL.Query().Get("role"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	limitStr := r.URL.Query().Get("limit")
	var limit int64 = 50
	if limitStr != "" {
		if val, err := strconv.ParseInt(limitStr, 10, 64); err == nil && val > 0 {
			limit = val
		}
	}

	users, err := h.store.ListUsers(r.Context(), role, status, limit)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to list users")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"data":   users,
	})
}

func (h Handler) SuspendUser(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("id"))
	if userID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "user id is required")
		return
	}

	var req struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	_ = httpx.DecodeJSON(r, &req)

	newStatus := "suspended"
	if req.Status == "active" || req.Status == "suspended" {
		newStatus = req.Status
	}

	if err := h.store.UpdateUserStatus(r.Context(), userID, newStatus); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to update user status")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"message": "user status updated successfully",
		"data": map[string]any{
			"id":     userID,
			"status": newStatus,
		},
	})
}

func (h Handler) GetUserActivity(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("id"))
	if userID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "user id is required")
		return
	}

	limitStr := r.URL.Query().Get("limit")
	var limit int64 = 50
	if limitStr != "" {
		if val, err := strconv.ParseInt(limitStr, 10, 64); err == nil && val > 0 {
			limit = val
		}
	}

	logs, err := h.store.ListAuditLogs(r.Context(), userID, "", limit)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to fetch user activity")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"data":   logs,
	})
}

func (h Handler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.URL.Query().Get("userId"))
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	limitStr := r.URL.Query().Get("limit")
	var limit int64 = 100
	if limitStr != "" {
		if val, err := strconv.ParseInt(limitStr, 10, 64); err == nil && val > 0 {
			limit = val
		}
	}

	logs, err := h.store.ListAuditLogs(r.Context(), userID, action, limit)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to list audit logs")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"data":   logs,
	})
}
