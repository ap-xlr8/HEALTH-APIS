package consent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"healthos/backend/internal/authz"
	"healthos/backend/internal/models"
	"healthos/backend/pkg/security"
)

func TestGrantHandler(t *testing.T) {
	store := &fakeStore{}
	broadcaster := &fakeBroadcaster{}
	handler := NewHandler(store, broadcaster)
	ctx := authz.WithClaims(context.Background(), &security.Claims{UserID: "usr_patient", Role: models.RolePatient})
	req := httptest.NewRequest(http.MethodPost, "/v1/consents", strings.NewReader(`{"caregiver_id":"usr_caregiver","scopes":["read:alerts","read:patient"]}`)).WithContext(ctx)
	res := httptest.NewRecorder()

	handler.Grant(res, req)

	if res.Code != http.StatusCreated || store.consent.PatientID != "usr_patient" || store.consent.CaregiverID != "usr_caregiver" {
		t.Fatalf("Grant status=%d consent=%+v", res.Code, store.consent)
	}
	if len(broadcaster.events) != 1 {
		t.Fatalf("expected consent.updated broadcast, got %d", len(broadcaster.events))
	}

	revokeReq := httptest.NewRequest(http.MethodDelete, "/v1/consents/usr_caregiver", nil).WithContext(ctx)
	revokeReq.SetPathValue("caregiver_id", "usr_caregiver")
	revokeRes := httptest.NewRecorder()
	handler.Revoke(revokeRes, revokeReq)
	if revokeRes.Code != http.StatusOK || !store.consent.Revoked {
		t.Fatalf("Revoke status=%d consent=%+v", revokeRes.Code, store.consent)
	}
}

func TestGrantHandlerRejectsInvalidInput(t *testing.T) {
	ctx := authz.WithClaims(context.Background(), &security.Claims{UserID: "usr_patient", Role: models.RolePatient})
	req := httptest.NewRequest(http.MethodPost, "/v1/consents", strings.NewReader(`{"caregiver_id":"","scopes":["read:alerts"]}`)).WithContext(ctx)
	res := httptest.NewRecorder()

	NewHandler(&fakeStore{}, &fakeBroadcaster{}).Grant(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", res.Code)
	}

	revokeReq := httptest.NewRequest(http.MethodDelete, "/v1/consents/usr_patient", nil).WithContext(ctx)
	revokeReq.SetPathValue("caregiver_id", "usr_patient")
	revokeRes := httptest.NewRecorder()
	NewHandler(&fakeStore{}, &fakeBroadcaster{}).Revoke(revokeRes, revokeReq)
	if revokeRes.Code != http.StatusBadRequest {
		t.Fatalf("revoke status=%d", revokeRes.Code)
	}
}
