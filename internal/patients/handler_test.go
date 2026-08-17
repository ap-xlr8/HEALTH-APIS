package patients

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"healthos/backend/internal/authz"
	"healthos/backend/internal/models"
	"healthos/backend/internal/store"
	"healthos/backend/pkg/security"
)

type fakePatientStore struct {
	user models.User
}

func (f fakePatientStore) FindUserByID(ctx context.Context, id string) (models.User, error) {
	if f.user.ID == id {
		return f.user, nil
	}
	return models.User{}, store.ErrNotFound
}

func (f fakePatientStore) UpdateUserHealthProfile(ctx context.Context, userID string, profile models.HealthProfile) error {
	if f.user.ID == userID {
		return nil
	}
	return store.ErrNotFound
}

func (f fakePatientStore) ListMedications(ctx context.Context, patientID string) ([]models.Medication, error) {
	return []models.Medication{}, nil
}

func TestGetPatient(t *testing.T) {
	t.Parallel()
	handler := New(fakePatientStore{user: models.User{ID: "usr_1", Role: models.RolePatient, FirstName: "Juan", LastName: "Perez", Age: 68}})
	req := httptest.NewRequest(http.MethodGet, "/v1/patients/usr_1", nil)
	req.SetPathValue("id", "usr_1")
	res := httptest.NewRecorder()

	handler.GetPatient(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", res.Code, res.Body.String())
	}
}

func TestGetPatientRejectsNonPatientAndMissing(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		user models.User
		id   string
		code int
	}{
		{name: "caregiver is not patient", user: models.User{ID: "cg_1", Role: models.RoleCaregiver}, id: "cg_1", code: http.StatusNotFound},
		{name: "missing", user: models.User{ID: "usr_1", Role: models.RolePatient}, id: "missing", code: http.StatusNotFound},
		{name: "bad id", user: models.User{ID: "usr_1", Role: models.RolePatient}, id: "", code: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := New(fakePatientStore{user: tc.user})
			req := httptest.NewRequest(http.MethodGet, "/v1/patients/"+tc.id, nil)
			req.SetPathValue("id", tc.id)
			res := httptest.NewRecorder()
			handler.GetPatient(res, req)
			if res.Code != tc.code {
				t.Fatalf("expected %d, got %d", res.Code, tc.code)
			}
		})
	}
}

func TestUpdateHealthProfile(t *testing.T) {
	t.Parallel()
	handler := New(fakePatientStore{user: models.User{ID: "usr_1", Role: models.RolePatient}})
	req := httptest.NewRequest(http.MethodPut, "/v1/patients/me/health-profile", strings.NewReader(`{
		"weight_kg":72.5,
		"height_cm":175,
		"blood_type":"O+",
		"rh_factor":"+",
		"birth_date":"1955-08-12",
		"biological_sex":"male",
		"phone":"+525512345678",
		"emergency_contact":{"name":"Maria","phone":"+525587654321","relationship":"spouse"},
		"baseline_vitals":{"resting_heart_rate":68.0,"baseline_spo2":98.0}
	}`))
	req = req.WithContext(authz.WithClaims(req.Context(), &security.Claims{UserID: "usr_1", Role: models.RolePatient}))
	res := httptest.NewRecorder()

	handler.UpdateHealthProfile(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"blood_type":"O+"`) {
		t.Fatalf("expected normalized blood type in response, got %s", res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"biological_sex":"male"`) {
		t.Fatalf("expected biological_sex in response, got %s", res.Body.String())
	}
}

func TestUpdateHealthProfileRejectsInvalid(t *testing.T) {
	t.Parallel()
	handler := New(fakePatientStore{user: models.User{ID: "usr_1", Role: models.RolePatient}})
	for name, body := range map[string]string{
		"bad blood type": `{"weight_kg":72.5,"height_cm":175,"blood_type":"XX"}`,
		"low weight":     `{"weight_kg":5,"height_cm":175,"blood_type":"O+"}`,
		"high weight":    `{"weight_kg":400,"height_cm":175,"blood_type":"O+"}`,
		"short height":   `{"weight_kg":72.5,"height_cm":10,"blood_type":"O+"}`,
		"bad json":       `{not json`,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/v1/patients/me/health-profile", strings.NewReader(body))
			req = req.WithContext(authz.WithClaims(req.Context(), &security.Claims{UserID: "usr_1", Role: models.RolePatient}))
			res := httptest.NewRecorder()
			handler.UpdateHealthProfile(res, req)
			if res.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d body=%s", res.Code, res.Body.String())
			}
		})
	}
}

func TestUpdateHealthProfileRequiresAuth(t *testing.T) {
	t.Parallel()
	handler := New(fakePatientStore{user: models.User{ID: "usr_1", Role: models.RolePatient}})
	req := httptest.NewRequest(http.MethodPut, "/v1/patients/me/health-profile", strings.NewReader(`{"weight_kg":72.5,"height_cm":175,"blood_type":"O+"}`))
	res := httptest.NewRecorder()

	handler.UpdateHealthProfile(res, req)

	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.Code)
	}
}
