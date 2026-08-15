package patients

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"healthos/backend/internal/models"
	"healthos/backend/internal/store"
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
				t.Fatalf("expected %d, got %d", tc.code, res.Code)
			}
		})
	}
}
