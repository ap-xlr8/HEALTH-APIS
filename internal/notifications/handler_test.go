package notifications

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"healthos/backend/internal/authz"
	"healthos/backend/internal/models"
	"healthos/backend/pkg/security"
)

type fakeStore struct {
	notification  models.Notification
	notifications []models.Notification
	err           error
}

func (f *fakeStore) CreateNotification(ctx context.Context, notification models.Notification) error {
	if f.err != nil {
		return f.err
	}
	f.notification = notification
	return nil
}

func (f *fakeStore) ListNotifications(ctx context.Context, userID string) ([]models.Notification, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.notifications, nil
}

func TestNotificationHandlers(t *testing.T) {
	store := &fakeStore{notifications: []models.Notification{{ID: "not_1"}}}
	handler := New(store)
	ctx := authz.WithClaims(context.Background(), &security.Claims{UserID: "usr_1", Role: models.RolePatient})
	req := httptest.NewRequest(http.MethodPost, "/v1/notifications", strings.NewReader(`{"channel":"push","title":"Vitals","body":"Review alert"}`)).WithContext(ctx)
	res := httptest.NewRecorder()
	handler.Create(res, req)
	if res.Code != http.StatusCreated || store.notification.ID == "" || store.notification.UserID != "usr_1" {
		t.Fatalf("Create status=%d notification=%+v", res.Code, store.notification)
	}
	listRes := httptest.NewRecorder()
	handler.List(listRes, httptest.NewRequest(http.MethodGet, "/v1/notifications", nil).WithContext(ctx))
	if listRes.Code != http.StatusOK {
		t.Fatalf("List status=%d", listRes.Code)
	}
}

func TestNotificationRejectsInvalidChannel(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/notifications", strings.NewReader(`{"channel":"fax","title":"x","body":"y"}`))
	res := httptest.NewRecorder()
	New(&fakeStore{}).Create(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", res.Code)
	}
}

func TestNotificationHandlersReturnStoreErrors(t *testing.T) {
	store := &fakeStore{err: errors.New("store down")}
	handler := New(store)
	ctx := authz.WithClaims(context.Background(), &security.Claims{UserID: "usr_1", Role: models.RolePatient})

	req := httptest.NewRequest(http.MethodPost, "/v1/notifications", strings.NewReader(`{"channel":"push","title":"Vitals","body":"Review alert"}`)).WithContext(ctx)
	res := httptest.NewRecorder()
	handler.Create(res, req)
	if res.Code != http.StatusInternalServerError {
		t.Fatalf("Create status=%d", res.Code)
	}

	listRes := httptest.NewRecorder()
	handler.List(listRes, httptest.NewRequest(http.MethodGet, "/v1/notifications", nil).WithContext(ctx))
	if listRes.Code != http.StatusInternalServerError {
		t.Fatalf("List status=%d", listRes.Code)
	}
}
