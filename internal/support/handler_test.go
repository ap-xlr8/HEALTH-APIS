package support

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
	ticket  models.SupportTicket
	tickets []models.SupportTicket
	err     error
}

func (f *fakeStore) CreateSupportTicket(ctx context.Context, ticket models.SupportTicket) error {
	if f.err != nil {
		return f.err
	}
	f.ticket = ticket
	return nil
}

func (f *fakeStore) ListSupportTickets(ctx context.Context, userID string) ([]models.SupportTicket, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.tickets, nil
}

func TestSupportHandlers(t *testing.T) {
	store := &fakeStore{tickets: []models.SupportTicket{{ID: "sup_1"}}}
	handler := New(store)
	ctx := authz.WithClaims(context.Background(), &security.Claims{UserID: "usr_1", Role: models.RolePatient})
	req := httptest.NewRequest(http.MethodPost, "/v1/support-tickets", strings.NewReader(`{"subject":"Help","body":"Need support"}`)).WithContext(ctx)
	res := httptest.NewRecorder()
	handler.Create(res, req)
	if res.Code != http.StatusCreated || store.ticket.ID == "" || store.ticket.Status != "open" {
		t.Fatalf("Create status=%d ticket=%+v", res.Code, store.ticket)
	}
	listRes := httptest.NewRecorder()
	handler.List(listRes, httptest.NewRequest(http.MethodGet, "/v1/support-tickets", nil).WithContext(ctx))
	if listRes.Code != http.StatusOK {
		t.Fatalf("List status=%d", listRes.Code)
	}
}

func TestSupportRejectsInvalidInput(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/support-tickets", strings.NewReader(`{"subject":"","body":"Need support"}`))
	res := httptest.NewRecorder()
	New(&fakeStore{}).Create(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", res.Code)
	}
}

func TestSupportHandlersReturnStoreErrors(t *testing.T) {
	store := &fakeStore{err: errors.New("store down")}
	handler := New(store)
	ctx := authz.WithClaims(context.Background(), &security.Claims{UserID: "usr_1", Role: models.RolePatient})

	req := httptest.NewRequest(http.MethodPost, "/v1/support-tickets", strings.NewReader(`{"subject":"Help","body":"Need support"}`)).WithContext(ctx)
	res := httptest.NewRecorder()
	handler.Create(res, req)
	if res.Code != http.StatusInternalServerError {
		t.Fatalf("Create status=%d", res.Code)
	}

	listRes := httptest.NewRecorder()
	handler.List(listRes, httptest.NewRequest(http.MethodGet, "/v1/support-tickets", nil).WithContext(ctx))
	if listRes.Code != http.StatusInternalServerError {
		t.Fatalf("List status=%d", listRes.Code)
	}
}
