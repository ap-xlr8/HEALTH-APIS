package devices

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"healthos/backend/internal/authz"
	"healthos/backend/internal/models"
	"healthos/backend/pkg/security"
)

type fakeStore struct {
	device      models.Device
	transfer    models.DeviceTransferRequest
	found       models.DeviceTransferRequest
	devices     []models.Device
	syncConfig  models.DeviceSyncConfig
	deviceErr   error
	transferErr error
	updateErr   error
}

func (f *fakeStore) CreateDevice(ctx context.Context, device models.Device) error {
	if f.deviceErr != nil {
		return f.deviceErr
	}
	f.device = device
	return nil
}

func (f *fakeStore) CreateDeviceTransferRequest(ctx context.Context, request models.DeviceTransferRequest) error {
	if f.transferErr != nil {
		return f.transferErr
	}
	f.transfer = request
	return nil
}

func (f *fakeStore) ListDevices(ctx context.Context, ownerID string) ([]models.Device, error) {
	return f.devices, nil
}

func (f *fakeStore) FindDeviceTransferRequestByID(ctx context.Context, id string) (models.DeviceTransferRequest, error) {
	if f.transferErr != nil {
		return models.DeviceTransferRequest{}, f.transferErr
	}
	return f.found, nil
}

func (f *fakeStore) UpdateDeviceTransferRequestStatus(ctx context.Context, id, status string, updatedAt time.Time) (models.DeviceTransferRequest, error) {
	if f.updateErr != nil {
		return models.DeviceTransferRequest{}, f.updateErr
	}
	f.transfer = f.found
	f.transfer.Status = status
	f.transfer.UpdatedAt = updatedAt
	return f.transfer, nil
}

func (f *fakeStore) FindDeviceByID(ctx context.Context, id string) (models.Device, error) {
	if f.deviceErr != nil {
		return models.Device{}, f.deviceErr
	}
	if f.device.ID == id {
		return f.device, nil
	}
	return models.Device{ID: id, OwnerID: "usr_1", Status: "active"}, nil
}

func (f *fakeStore) UpdateDeviceOwner(ctx context.Context, id, ownerID string, updatedAt time.Time) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	f.device.ID = id
	f.device.OwnerID = ownerID
	f.device.UpdatedAt = updatedAt
	return nil
}

func (f *fakeStore) GetDeviceSyncConfig(ctx context.Context, deviceID string) (models.DeviceSyncConfig, error) {
	if f.syncConfig.DeviceID == "" {
		return models.DeviceSyncConfig{
			DeviceID:           deviceID,
			SamplingIntervalMs: 1000,
			BatchSize:          50,
		}, nil
	}
	return f.syncConfig, nil
}

func (f *fakeStore) UpdateDeviceSyncConfig(ctx context.Context, config models.DeviceSyncConfig) error {
	f.syncConfig = config
	return nil
}

func TestRegisterWearable(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	service := New(store)

	device, err := service.RegisterWearable(context.Background(), " usr_1 ", " SN-123 ", " wearable ")
	if err != nil {
		t.Fatalf("RegisterWearable returned error: %v", err)
	}
	if device.ID == "" || device.OwnerID != "usr_1" || device.SerialNumber != "SN-123" || device.Status != "active" {
		t.Fatalf("unexpected device: %#v", device)
	}
	if store.device.ID != device.ID {
		t.Fatalf("device was not persisted: %#v", store.device)
	}
}

func TestRegisterWearableRejectsInvalidInputAndStoreErrors(t *testing.T) {
	t.Parallel()
	service := New(&fakeStore{})
	for _, tc := range []struct {
		name         string
		ownerID      string
		serialNumber string
		deviceType   string
	}{
		{name: "missing owner", serialNumber: "SN", deviceType: "wearable"},
		{name: "missing serial", ownerID: "usr_1", deviceType: "wearable"},
		{name: "missing type", ownerID: "usr_1", serialNumber: "SN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := service.RegisterWearable(context.Background(), tc.ownerID, tc.serialNumber, tc.deviceType); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	failing := New(&fakeStore{deviceErr: errors.New("db down")})
	if _, err := failing.RegisterWearable(context.Background(), "usr_1", "SN", "wearable"); err == nil {
		t.Fatal("expected store error")
	}
}

func TestRequestTransfer(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	service := New(store)

	request, err := service.RequestTransfer(context.Background(), " dev_1 ", "usr_1", "usr_2")
	if err != nil {
		t.Fatalf("RequestTransfer returned error: %v", err)
	}
	if request.ID == "" || request.DeviceID != "dev_1" || request.Status != "pending" || request.FromOwnerID != "usr_1" || request.ToOwnerID != "usr_2" {
		t.Fatalf("unexpected transfer request: %#v", request)
	}
	if store.transfer.ID != request.ID {
		t.Fatalf("transfer request was not persisted: %#v", store.transfer)
	}
}

func TestRequestTransferRejectsInvalidInputAndStoreErrors(t *testing.T) {
	t.Parallel()
	service := New(&fakeStore{})
	for _, tc := range []struct {
		name        string
		deviceID    string
		fromOwnerID string
		toOwnerID   string
	}{
		{name: "missing device", fromOwnerID: "usr_1", toOwnerID: "usr_2"},
		{name: "missing from", deviceID: "dev_1", toOwnerID: "usr_2"},
		{name: "missing to", deviceID: "dev_1", fromOwnerID: "usr_1"},
		{name: "same owner", deviceID: "dev_1", fromOwnerID: "usr_1", toOwnerID: "usr_1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := service.RequestTransfer(context.Background(), tc.deviceID, tc.fromOwnerID, tc.toOwnerID); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	failing := New(&fakeStore{transferErr: errors.New("db down")})
	if _, err := failing.RequestTransfer(context.Background(), "dev_1", "usr_1", "usr_2"); err == nil {
		t.Fatal("expected store error")
	}
}

func TestApproveAndRejectTransfer(t *testing.T) {
	store := &fakeStore{found: models.DeviceTransferRequest{ID: "dtr_1", DeviceID: "dev_1", FromOwnerID: "usr_1", ToOwnerID: "usr_2", Status: "pending"}}
	approved, err := New(store).ApproveTransfer(context.Background(), "dtr_1", "usr_2")
	if err != nil {
		t.Fatalf("ApproveTransfer returned error: %v", err)
	}
	if approved.Status != "approved" || store.device.OwnerID != "usr_2" {
		t.Fatalf("unexpected approval state approved=%#v device=%#v", approved, store.device)
	}

	store = &fakeStore{found: models.DeviceTransferRequest{ID: "dtr_2", DeviceID: "dev_1", FromOwnerID: "usr_1", ToOwnerID: "usr_2", Status: "pending"}}
	rejected, err := New(store).RejectTransfer(context.Background(), "dtr_2", "usr_1")
	if err != nil {
		t.Fatalf("RejectTransfer returned error: %v", err)
	}
	if rejected.Status != "rejected" {
		t.Fatalf("unexpected rejection: %#v", rejected)
	}
}

func TestCompleteTransferRejectsInvalidActorsAndStates(t *testing.T) {
	service := New(&fakeStore{found: models.DeviceTransferRequest{ID: "dtr_1", DeviceID: "dev_1", FromOwnerID: "usr_1", ToOwnerID: "usr_2", Status: "pending"}})
	if _, err := service.ApproveTransfer(context.Background(), "dtr_1", "usr_1"); err == nil {
		t.Fatal("expected approve actor validation error")
	}
	if _, err := service.RejectTransfer(context.Background(), "dtr_1", "usr_3"); err == nil {
		t.Fatal("expected reject actor validation error")
	}
	notPending := New(&fakeStore{found: models.DeviceTransferRequest{ID: "dtr_1", Status: "approved", ToOwnerID: "usr_2"}})
	if _, err := notPending.ApproveTransfer(context.Background(), "dtr_1", "usr_2"); err == nil {
		t.Fatal("expected pending validation error")
	}
	failing := New(&fakeStore{found: models.DeviceTransferRequest{ID: "dtr_1", DeviceID: "dev_1", FromOwnerID: "usr_1", ToOwnerID: "usr_2", Status: "pending"}, updateErr: errors.New("db down")})
	if _, err := failing.ApproveTransfer(context.Background(), "dtr_1", "usr_2"); err == nil {
		t.Fatal("expected update error")
	}
}

func TestDeviceHandlers(t *testing.T) {
	store := &fakeStore{devices: []models.Device{{ID: "dev_1", OwnerID: "usr_1"}}}
	handler := NewHandler(store)
	ctx := authz.WithClaims(context.Background(), &security.Claims{UserID: "usr_1", Role: models.RolePatient})

	registerReq := httptest.NewRequest(http.MethodPost, "/v1/devices", strings.NewReader(`{"serial_number":"SN-1","type":"wearable"}`)).WithContext(ctx)
	registerRes := httptest.NewRecorder()
	handler.RegisterWearable(registerRes, registerReq)
	if registerRes.Code != http.StatusCreated || store.device.ID == "" || store.device.OwnerID != "usr_1" {
		t.Fatalf("RegisterWearable status=%d device=%+v", registerRes.Code, store.device)
	}

	listRes := httptest.NewRecorder()
	handler.ListDevices(listRes, httptest.NewRequest(http.MethodGet, "/v1/devices", nil).WithContext(ctx))
	if listRes.Code != http.StatusOK {
		t.Fatalf("ListDevices status=%d", listRes.Code)
	}

	transferReq := httptest.NewRequest(http.MethodPost, "/v1/devices/dev_1/transfer-requests", strings.NewReader(`{"to_owner_id":"usr_2"}`)).WithContext(ctx)
	transferReq.SetPathValue("id", "dev_1")
	transferRes := httptest.NewRecorder()
	handler.RequestTransfer(transferRes, transferReq)
	if transferRes.Code != http.StatusCreated || store.transfer.ID == "" || store.transfer.ToOwnerID != "usr_2" {
		t.Fatalf("RequestTransfer status=%d transfer=%+v", transferRes.Code, store.transfer)
	}

	store.found = models.DeviceTransferRequest{ID: "dtr_1", DeviceID: "dev_1", FromOwnerID: "usr_1", ToOwnerID: "usr_1", Status: "pending"}
	approveReq := httptest.NewRequest(http.MethodPost, "/v1/device-transfer-requests/dtr_1/approve", nil).WithContext(ctx)
	approveReq.SetPathValue("id", "dtr_1")
	approveRes := httptest.NewRecorder()
	handler.ApproveTransfer(approveRes, approveReq)
	if approveRes.Code != http.StatusOK || store.transfer.Status != "approved" {
		t.Fatalf("ApproveTransfer status=%d transfer=%+v", approveRes.Code, store.transfer)
	}

	store.found = models.DeviceTransferRequest{ID: "dtr_2", DeviceID: "dev_1", FromOwnerID: "usr_1", ToOwnerID: "usr_2", Status: "pending"}
	rejectReq := httptest.NewRequest(http.MethodPost, "/v1/device-transfer-requests/dtr_2/reject", nil).WithContext(ctx)
	rejectReq.SetPathValue("id", "dtr_2")
	rejectRes := httptest.NewRecorder()
	handler.RejectTransfer(rejectRes, rejectReq)
	if rejectRes.Code != http.StatusOK || store.transfer.Status != "rejected" {
		t.Fatalf("RejectTransfer status=%d transfer=%+v", rejectRes.Code, store.transfer)
	}

	configReq := httptest.NewRequest(http.MethodGet, "/v1/devices/dev_1/sync-config", nil).WithContext(ctx)
	configReq.SetPathValue("id", "dev_1")
	configRes := httptest.NewRecorder()
	handler.GetSyncConfig(configRes, configReq)
	if configRes.Code != http.StatusOK {
		t.Fatalf("GetSyncConfig status=%d", configRes.Code)
	}
}

func TestDeviceHandlersRejectInvalidInput(t *testing.T) {
	handler := NewHandler(&fakeStore{})
	ctx := authz.WithClaims(context.Background(), &security.Claims{UserID: "usr_1", Role: models.RolePatient})

	registerRes := httptest.NewRecorder()
	handler.RegisterWearable(registerRes, httptest.NewRequest(http.MethodPost, "/v1/devices", strings.NewReader(`{"serial_number":"","type":"wearable"}`)).WithContext(ctx))
	if registerRes.Code != http.StatusBadRequest {
		t.Fatalf("RegisterWearable status=%d", registerRes.Code)
	}

	transferReq := httptest.NewRequest(http.MethodPost, "/v1/devices/dev_1/transfer-requests", strings.NewReader(`{"to_owner_id":"usr_1"}`)).WithContext(ctx)
	transferReq.SetPathValue("id", "dev_1")
	transferRes := httptest.NewRecorder()
	handler.RequestTransfer(transferRes, transferReq)
	if transferRes.Code != http.StatusBadRequest {
		t.Fatalf("RequestTransfer status=%d", transferRes.Code)
	}
}
