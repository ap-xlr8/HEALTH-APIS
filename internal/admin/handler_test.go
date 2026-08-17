package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"healthos/backend/internal/models"
)

type mockAdminStore struct {
	users []models.User
	logs  []models.AuditLog
}

func (m *mockAdminStore) ListUsers(ctx context.Context, role, status string, limit int64) ([]models.User, error) {
	return m.users, nil
}

func (m *mockAdminStore) FindUserByID(ctx context.Context, id string) (models.User, error) {
	for _, u := range m.users {
		if u.ID == id {
			return u, nil
		}
	}
	return models.User{}, nil
}

func (m *mockAdminStore) UpdateUserStatus(ctx context.Context, userID, status string) error {
	return nil
}

func (m *mockAdminStore) ListAuditLogs(ctx context.Context, userID, action string, limit int64) ([]models.AuditLog, error) {
	return m.logs, nil
}

func TestAdminHandler_ListUsers(t *testing.T) {
	store := &mockAdminStore{
		users: []models.User{
			{ID: "usr_1", Email: "test@example.com", Role: "patient", Status: "active", CreatedAt: time.Now()},
		},
	}
	h := New(store)

	req := httptest.NewRequest("GET", "/v1/admin/users", nil)
	rec := httptest.NewRecorder()

	h.ListUsers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "test@example.com") {
		t.Fatalf("expected response to contain user email, got %s", rec.Body.String())
	}
}

func TestAdminHandler_SuspendUser(t *testing.T) {
	store := &mockAdminStore{}
	h := New(store)

	req := httptest.NewRequest("POST", "/v1/admin/users/usr_1/suspend", strings.NewReader(`{"status":"suspended","reason":"policy violation"}`))
	req.SetPathValue("id", "usr_1")
	rec := httptest.NewRecorder()

	h.SuspendUser(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "suspended") {
		t.Fatalf("expected response to contain suspended status, got %s", rec.Body.String())
	}
}

func TestAdminHandler_ListAuditLogs(t *testing.T) {
	store := &mockAdminStore{
		logs: []models.AuditLog{
			{ID: "log_1", UserID: "usr_1", Action: "login", Resource: "auth", Allowed: true, CreatedAt: time.Now()},
		},
	}
	h := New(store)

	req := httptest.NewRequest("GET", "/v1/admin/audit", nil)
	rec := httptest.NewRecorder()

	h.ListAuditLogs(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "login") {
		t.Fatalf("expected response to contain log action, got %s", rec.Body.String())
	}
}
