package relationships

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
	relationship  models.Relationship
	relationships []models.Relationship
	err           error
}

func (f *fakeStore) UpsertRelationship(ctx context.Context, relationship models.Relationship) error {
	if f.err != nil {
		return f.err
	}
	f.relationship = relationship
	return nil
}

func (f *fakeStore) ListRelationshipsForUser(ctx context.Context, userID, role string) ([]models.Relationship, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.relationships, nil
}

func (f *fakeStore) FindUserByEmail(ctx context.Context, email string) (models.User, error) {
	if f.err != nil {
		return models.User{}, f.err
	}
	return models.User{ID: "usr_from_email", Email: email}, nil
}

func (f *fakeStore) FindUserByID(ctx context.Context, id string) (models.User, error) {
	if f.err != nil {
		return models.User{}, f.err
	}
	return models.User{ID: id}, nil
}

func TestAssignCaregiver(t *testing.T) {
	store := &fakeStore{}
	relationship, err := New(store).AssignCaregiver(context.Background(), " usr_patient ", " usr_caregiver ")
	if err != nil {
		t.Fatalf("AssignCaregiver returned error: %v", err)
	}
	if relationship.ID == "" || relationship.PatientID != "usr_patient" || relationship.CaregiverID != "usr_caregiver" || relationship.Status != "active" {
		t.Fatalf("unexpected relationship: %#v", relationship)
	}
	if store.relationship.ID != relationship.ID {
		t.Fatalf("relationship was not persisted: %#v", store.relationship)
	}
}

func TestRevokeCaregiver(t *testing.T) {
	store := &fakeStore{}
	relationship, err := New(store).RevokeCaregiver(context.Background(), " usr_patient ", " usr_caregiver ")
	if err != nil {
		t.Fatalf("RevokeCaregiver returned error: %v", err)
	}
	if relationship.ID == "" || relationship.Status != "revoked" || relationship.PatientID != "usr_patient" || relationship.CaregiverID != "usr_caregiver" {
		t.Fatalf("unexpected revoked relationship: %#v", relationship)
	}
	if store.relationship.Status != "revoked" {
		t.Fatalf("relationship was not persisted as revoked: %#v", store.relationship)
	}
}

func TestAssignCaregiverRejectsInvalidInputAndStoreErrors(t *testing.T) {
	service := New(&fakeStore{})
	for _, tc := range []struct {
		name        string
		patientID   string
		caregiverID string
	}{
		{name: "missing patient", caregiverID: "usr_caregiver"},
		{name: "missing caregiver", patientID: "usr_patient"},
		{name: "same user", patientID: "usr_1", caregiverID: "usr_1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := service.AssignCaregiver(context.Background(), tc.patientID, tc.caregiverID); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	if _, err := New(&fakeStore{err: errors.New("db down")}).AssignCaregiver(context.Background(), "usr_1", "usr_2"); err == nil {
		t.Fatal("expected store error")
	}
	if _, err := service.RevokeCaregiver(context.Background(), "usr_1", "usr_1"); err == nil {
		t.Fatal("expected revoke validation error")
	}
	if _, err := New(&fakeStore{err: errors.New("db down")}).RevokeCaregiver(context.Background(), "usr_1", "usr_2"); err == nil {
		t.Fatal("expected revoke store error")
	}
}

func TestRelationshipHandlers(t *testing.T) {
	store := &fakeStore{relationships: []models.Relationship{{ID: "rel_1", PatientID: "usr_patient", CaregiverID: "usr_caregiver", Status: "active"}}}
	handler := NewHandler(store)
	ctx := authz.WithClaims(context.Background(), &security.Claims{UserID: "usr_patient", Role: models.RolePatient})

	assignReq := httptest.NewRequest(http.MethodPost, "/v1/relationships", strings.NewReader(`{"caregiver_id":"usr_caregiver"}`)).WithContext(ctx)
	assignRes := httptest.NewRecorder()
	handler.AssignCaregiver(assignRes, assignReq)
	if assignRes.Code != http.StatusCreated || store.relationship.PatientID != "usr_patient" {
		t.Fatalf("AssignCaregiver status=%d relationship=%+v", assignRes.Code, store.relationship)
	}

	revokeReq := httptest.NewRequest(http.MethodDelete, "/v1/relationships/usr_caregiver", nil).WithContext(ctx)
	revokeReq.SetPathValue("caregiver_id", "usr_caregiver")
	revokeRes := httptest.NewRecorder()
	handler.RevokeCaregiver(revokeRes, revokeReq)
	if revokeRes.Code != http.StatusOK || store.relationship.Status != "revoked" {
		t.Fatalf("RevokeCaregiver status=%d relationship=%+v", revokeRes.Code, store.relationship)
	}

	listRes := httptest.NewRecorder()
	handler.List(listRes, httptest.NewRequest(http.MethodGet, "/v1/relationships", nil).WithContext(ctx))
	if listRes.Code != http.StatusOK {
		t.Fatalf("List status=%d", listRes.Code)
	}
}

func TestRelationshipHandlerRejectsInvalidInput(t *testing.T) {
	ctx := authz.WithClaims(context.Background(), &security.Claims{UserID: "usr_patient", Role: models.RolePatient})
	req := httptest.NewRequest(http.MethodPost, "/v1/relationships", strings.NewReader(`{"caregiver_id":""}`)).WithContext(ctx)
	res := httptest.NewRecorder()
	NewHandler(&fakeStore{}).AssignCaregiver(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", res.Code)
	}

	badJSON := httptest.NewRequest(http.MethodPost, "/v1/relationships", strings.NewReader(`{`)).WithContext(ctx)
	badJSONRes := httptest.NewRecorder()
	NewHandler(&fakeStore{}).AssignCaregiver(badJSONRes, badJSON)
	if badJSONRes.Code != http.StatusBadRequest {
		t.Fatalf("bad json status=%d", badJSONRes.Code)
	}
}

func TestRelationshipHandlerListStoreError(t *testing.T) {
	ctx := authz.WithClaims(context.Background(), &security.Claims{UserID: "usr_patient", Role: models.RolePatient})
	res := httptest.NewRecorder()
	NewHandler(&fakeStore{err: errors.New("db down")}).List(res, httptest.NewRequest(http.MethodGet, "/v1/relationships", nil).WithContext(ctx))
	if res.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", res.Code)
	}
}
