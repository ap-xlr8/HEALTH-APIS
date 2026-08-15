package devices

import (
	"context"
	"net/http"
	"strings"
	"time"

	"healthos/backend/internal/authz"
	"healthos/backend/internal/models"
	"healthos/backend/pkg/httpx"
)

type HandlerStore interface {
	CreateDevice(ctx context.Context, device models.Device) error
	FindDeviceByID(ctx context.Context, id string) (models.Device, error)
	CreateDeviceTransferRequest(ctx context.Context, request models.DeviceTransferRequest) error
	FindDeviceTransferRequestByID(ctx context.Context, id string) (models.DeviceTransferRequest, error)
	UpdateDeviceTransferRequestStatus(ctx context.Context, id, status string, updatedAt time.Time) (models.DeviceTransferRequest, error)
	UpdateDeviceOwner(ctx context.Context, id, ownerID string, updatedAt time.Time) error
	ListDevices(ctx context.Context, ownerID string) ([]models.Device, error)
}

type Handler struct {
	store HandlerStore
}

func NewHandler(store HandlerStore) Handler {
	return Handler{store: store}
}

func (h Handler) RegisterWearable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SerialNumber string `json:"serial_number"`
		Type         string `json:"type"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	claims, _ := authz.ClaimsFromContext(r.Context())
	device, err := New(h.store).RegisterWearable(r.Context(), claims.UserID, req.SerialNumber, req.Type)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"status": "success", "data": device})
}

func (h Handler) ListDevices(w http.ResponseWriter, r *http.Request) {
	claims, _ := authz.ClaimsFromContext(r.Context())
	devices, err := h.store.ListDevices(r.Context(), claims.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list devices")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "data": devices})
}

func (h Handler) RequestTransfer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ToOwnerID string `json:"to_owner_id"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	claims, _ := authz.ClaimsFromContext(r.Context())
	request, err := New(h.store).RequestTransfer(r.Context(), strings.TrimSpace(r.PathValue("id")), claims.UserID, req.ToOwnerID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"status": "success", "data": request})
}

func (h Handler) ApproveTransfer(w http.ResponseWriter, r *http.Request) {
	claims, _ := authz.ClaimsFromContext(r.Context())
	request, err := New(h.store).ApproveTransfer(r.Context(), strings.TrimSpace(r.PathValue("id")), claims.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "data": request})
}

func (h Handler) RejectTransfer(w http.ResponseWriter, r *http.Request) {
	claims, _ := authz.ClaimsFromContext(r.Context())
	request, err := New(h.store).RejectTransfer(r.Context(), strings.TrimSpace(r.PathValue("id")), claims.UserID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "data": request})
}
