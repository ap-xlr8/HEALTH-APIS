package breakglass

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"healthos/backend/internal/audit"
	"healthos/backend/internal/authz"
	"healthos/backend/internal/models"
	"healthos/backend/internal/store"
	"healthos/backend/pkg/httpx"
)

const maxDuration = 2 * time.Hour

type Store interface {
	CreateBreakGlassRequest(ctx context.Context, request models.BreakGlassRequest) error
	FindBreakGlassRequestByID(ctx context.Context, id string) (models.BreakGlassRequest, error)
	ApproveBreakGlassRequest(ctx context.Context, id, approverID string, approvedAt time.Time) (models.BreakGlassRequest, error)
	WriteAudit(ctx context.Context, log models.AuditLog) error
}

type Handler struct {
	store Store
}

func New(store Store) Handler {
	return Handler{store: store}
}

type requestBody struct {
	Reason          string `json:"reason"`
	DurationMinutes int    `json:"duration_minutes"`
}

func (h Handler) Request(w http.ResponseWriter, r *http.Request) {
	claims, ok := authz.ClaimsFromContext(r.Context())
	if !ok || claims.Role != models.RoleAdmin {
		httpx.WriteError(w, http.StatusForbidden, "admin role required")
		return
	}
	var req requestBody
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" || len(reason) > 1000 {
		httpx.WriteError(w, http.StatusBadRequest, "reason is required and must be <= 1000 characters")
		return
	}
	if req.DurationMinutes < 1 || time.Duration(req.DurationMinutes)*time.Minute > maxDuration {
		httpx.WriteError(w, http.StatusBadRequest, "duration_minutes must be between 1 and 120")
		return
	}
	now := time.Now().UTC()
	breakGlass := models.BreakGlassRequest{
		ID:          "bgr_" + uuid.NewString(),
		RequesterID: claims.UserID,
		Reason:      reason,
		Status:      "pending",
		ExpiresAt:   now.Add(time.Duration(req.DurationMinutes) * time.Minute),
		CreatedAt:   now,
	}
	if err := h.store.CreateBreakGlassRequest(r.Context(), breakGlass); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "break-glass request persistence failed")
		return
	}
	h.audit(r.Context(), claims.UserID, true, "break_glass.requested", breakGlass.ID, map[string]any{"expires_at": breakGlass.ExpiresAt})
	httpx.WriteJSON(w, http.StatusCreated, breakGlass)
}

func (h Handler) Approve(w http.ResponseWriter, r *http.Request) {
	claims, ok := authz.ClaimsFromContext(r.Context())
	if !ok || claims.Role != models.RoleAdmin {
		httpx.WriteError(w, http.StatusForbidden, "admin role required")
		return
	}
	id := r.PathValue("id")
	if id == "" || len(id) > 80 {
		httpx.WriteError(w, http.StatusBadRequest, "break-glass request id is required")
		return
	}
	existing, err := h.store.FindBreakGlassRequestByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "break-glass request not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "break-glass lookup failed")
		return
	}
	if existing.RequesterID == claims.UserID {
		h.audit(r.Context(), claims.UserID, false, "break_glass.approve", id, map[string]any{"reason": "two-person rule required"})
		httpx.WriteError(w, http.StatusForbidden, "two-person rule requires a different approving admin")
		return
	}
	if existing.Status != "pending" || time.Now().UTC().After(existing.ExpiresAt) {
		h.audit(r.Context(), claims.UserID, false, "break_glass.approve", id, map[string]any{"status": existing.Status})
		httpx.WriteError(w, http.StatusConflict, "break-glass request is not pending or has expired")
		return
	}
	approved, err := h.store.ApproveBreakGlassRequest(r.Context(), id, claims.UserID, time.Now().UTC())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteError(w, http.StatusConflict, "break-glass request cannot be approved")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "break-glass approval failed")
		return
	}
	h.audit(r.Context(), claims.UserID, true, "break_glass.approved", approved.ID, map[string]any{"requester_id": approved.RequesterID})
	httpx.WriteJSON(w, http.StatusOK, approved)
}

func (h Handler) audit(ctx context.Context, userID string, allowed bool, action, resource string, metadata map[string]any) {
	_ = audit.NewRecorder(h.store).Record(ctx, audit.Entry{
		UserID:   userID,
		Action:   action,
		Resource: resource,
		Allowed:  allowed,
		Metadata: metadata,
	})
}
