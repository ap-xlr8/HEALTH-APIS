package devices

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"healthos/backend/internal/models"
)

type Store interface {
	CreateDevice(ctx context.Context, device models.Device) error
	FindDeviceByID(ctx context.Context, id string) (models.Device, error)
	CreateDeviceTransferRequest(ctx context.Context, request models.DeviceTransferRequest) error
	FindDeviceTransferRequestByID(ctx context.Context, id string) (models.DeviceTransferRequest, error)
	UpdateDeviceTransferRequestStatus(ctx context.Context, id, status string, updatedAt time.Time) (models.DeviceTransferRequest, error)
	UpdateDeviceOwner(ctx context.Context, id, ownerID string, updatedAt time.Time) error
}

type Service struct {
	store Store
}

func New(store Store) Service {
	return Service{store: store}
}

func (s Service) RegisterWearable(ctx context.Context, ownerID, serialNumber, deviceType string) (models.Device, error) {
	ownerID = strings.TrimSpace(ownerID)
	serialNumber = strings.TrimSpace(serialNumber)
	deviceType = strings.TrimSpace(deviceType)
	if ownerID == "" || len(ownerID) > 80 {
		return models.Device{}, errors.New("owner_id is required and must be <= 80 characters")
	}
	if serialNumber == "" || len(serialNumber) > 128 {
		return models.Device{}, errors.New("serial_number is required and must be <= 128 characters")
	}
	if deviceType == "" || len(deviceType) > 40 {
		return models.Device{}, errors.New("type is required and must be <= 40 characters")
	}
	now := time.Now().UTC()
	device := models.Device{
		ID:           "dev_" + uuid.NewString(),
		OwnerID:      ownerID,
		SerialNumber: serialNumber,
		Type:         deviceType,
		Status:       "active",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.store.CreateDevice(ctx, device); err != nil {
		return models.Device{}, err
	}
	return device, nil
}

func (s Service) RequestTransfer(ctx context.Context, deviceID, fromOwnerID, toOwnerID string) (models.DeviceTransferRequest, error) {
	deviceID = strings.TrimSpace(deviceID)
	fromOwnerID = strings.TrimSpace(fromOwnerID)
	toOwnerID = strings.TrimSpace(toOwnerID)
	if deviceID == "" || len(deviceID) > 80 {
		return models.DeviceTransferRequest{}, errors.New("device_id is required and must be <= 80 characters")
	}
	if fromOwnerID == "" || toOwnerID == "" {
		return models.DeviceTransferRequest{}, errors.New("from_owner_id and to_owner_id are required")
	}
	if fromOwnerID == toOwnerID {
		return models.DeviceTransferRequest{}, errors.New("device transfer requires different owners")
	}

	device, err := s.store.FindDeviceByID(ctx, deviceID)
	if err != nil {
		return models.DeviceTransferRequest{}, errors.New("device not found")
	}
	if device.OwnerID != fromOwnerID {
		return models.DeviceTransferRequest{}, errors.New("device does not belong to the requesting owner")
	}
	if device.Status != "active" {
		return models.DeviceTransferRequest{}, errors.New("only active devices can be transferred")
	}

	now := time.Now().UTC()
	request := models.DeviceTransferRequest{
		ID:          "dtr_" + uuid.NewString(),
		DeviceID:    deviceID,
		FromOwnerID: fromOwnerID,
		ToOwnerID:   toOwnerID,
		Status:      "pending",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.store.CreateDeviceTransferRequest(ctx, request); err != nil {
		return models.DeviceTransferRequest{}, err
	}
	return request, nil
}

func (s Service) ApproveTransfer(ctx context.Context, requestID, actorID string) (models.DeviceTransferRequest, error) {
	request, err := s.resolvePendingTransfer(ctx, requestID, actorID)
	if err != nil {
		return models.DeviceTransferRequest{}, err
	}
	if actorID != request.ToOwnerID {
		return models.DeviceTransferRequest{}, errors.New("only the target owner can approve a device transfer")
	}
	now := time.Now().UTC()
	updated, err := s.store.UpdateDeviceTransferRequestStatus(ctx, request.ID, "approved", now)
	if err != nil {
		return models.DeviceTransferRequest{}, err
	}
	if err := s.store.UpdateDeviceOwner(ctx, request.DeviceID, request.ToOwnerID, now); err != nil {
		return models.DeviceTransferRequest{}, err
	}
	return updated, nil
}

func (s Service) RejectTransfer(ctx context.Context, requestID, actorID string) (models.DeviceTransferRequest, error) {
	request, err := s.resolvePendingTransfer(ctx, requestID, actorID)
	if err != nil {
		return models.DeviceTransferRequest{}, err
	}
	if actorID != request.FromOwnerID && actorID != request.ToOwnerID {
		return models.DeviceTransferRequest{}, errors.New("only transfer participants can reject a device transfer")
	}
	return s.store.UpdateDeviceTransferRequestStatus(ctx, request.ID, "rejected", time.Now().UTC())
}

func (s Service) resolvePendingTransfer(ctx context.Context, requestID, actorID string) (models.DeviceTransferRequest, error) {
	requestID = strings.TrimSpace(requestID)
	actorID = strings.TrimSpace(actorID)
	if requestID == "" || len(requestID) > 80 || actorID == "" || len(actorID) > 80 {
		return models.DeviceTransferRequest{}, errors.New("request_id and actor_id are required")
	}
	request, err := s.store.FindDeviceTransferRequestByID(ctx, requestID)
	if err != nil {
		return models.DeviceTransferRequest{}, err
	}
	if request.Status != "pending" {
		return models.DeviceTransferRequest{}, errors.New("device transfer request is not pending")
	}
	return request, nil
}
