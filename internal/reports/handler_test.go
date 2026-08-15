package reports

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
	report  models.Report
	reports []models.Report
	err     error
}

func (f *fakeStore) CreateReport(ctx context.Context, report models.Report) error {
	if f.err != nil {
		return f.err
	}
	f.report = report
	return nil
}

func (f *fakeStore) ListReports(ctx context.Context, patientID string) ([]models.Report, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.reports, nil
}

func TestReportsHandlers(t *testing.T) {
	store := &fakeStore{reports: []models.Report{{ID: "rep_1"}}}
	handler := New(store)
	ctx := authz.WithClaims(context.Background(), &security.Claims{UserID: "admin_1", Role: models.RoleAdmin})
	req := httptest.NewRequest(http.MethodPost, "/v1/patients/usr_1/reports", strings.NewReader(`{"url":"s3://reports/rep_1.pdf","format":"pdf"}`)).WithContext(ctx)
	req.SetPathValue("id", "usr_1")
	res := httptest.NewRecorder()
	handler.Create(res, req)
	if res.Code != http.StatusCreated || store.report.ID == "" || store.report.CreatedBy != "admin_1" {
		t.Fatalf("Create status=%d report=%+v", res.Code, store.report)
	}
	listReq := httptest.NewRequest(http.MethodGet, "/v1/patients/usr_1/reports", nil)
	listReq.SetPathValue("id", "usr_1")
	listRes := httptest.NewRecorder()
	handler.List(listRes, listReq)
	if listRes.Code != http.StatusOK {
		t.Fatalf("List status=%d", listRes.Code)
	}
}

func TestReportsRejectInvalidInput(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/patients/usr_1/reports", strings.NewReader(`{"url":"https://example.com/rep.pdf","format":"pdf"}`))
	req.SetPathValue("id", "usr_1")
	res := httptest.NewRecorder()
	New(&fakeStore{}).Create(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", res.Code)
	}
}

func TestReportHandlersReturnStoreErrors(t *testing.T) {
	store := &fakeStore{err: errors.New("store down")}
	handler := New(store)
	ctx := authz.WithClaims(context.Background(), &security.Claims{UserID: "admin_1", Role: models.RoleAdmin})

	req := httptest.NewRequest(http.MethodPost, "/v1/patients/usr_1/reports", strings.NewReader(`{"url":"s3://reports/rep_1.pdf","format":"pdf"}`)).WithContext(ctx)
	req.SetPathValue("id", "usr_1")
	res := httptest.NewRecorder()
	handler.Create(res, req)
	if res.Code != http.StatusInternalServerError {
		t.Fatalf("Create status=%d", res.Code)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/v1/patients/usr_1/reports", nil)
	listReq.SetPathValue("id", "usr_1")
	listRes := httptest.NewRecorder()
	handler.List(listRes, listReq)
	if listRes.Code != http.StatusInternalServerError {
		t.Fatalf("List status=%d", listRes.Code)
	}
}
