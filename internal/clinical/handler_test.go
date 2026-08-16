package clinical

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

type fakeClinicalStore struct {
	record      models.ClinicalRecord
	medication  models.Medication
	log         models.MedicationLog
	records     []models.ClinicalRecord
	medications []models.Medication
	adherence   float64
	err         error
}

func (f *fakeClinicalStore) CreateClinicalRecord(ctx context.Context, record models.ClinicalRecord) error {
	if f.err != nil {
		return f.err
	}
	f.record = record
	return nil
}

func (f *fakeClinicalStore) ListClinicalRecords(ctx context.Context, patientID string) ([]models.ClinicalRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.records, nil
}

func (f *fakeClinicalStore) CreateMedication(ctx context.Context, medication models.Medication) error {
	if f.err != nil {
		return f.err
	}
	f.medication = medication
	return nil
}

func (f *fakeClinicalStore) ListMedications(ctx context.Context, patientID string) ([]models.Medication, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.medications, nil
}

func (f *fakeClinicalStore) RecordMedicationLog(ctx context.Context, log models.MedicationLog) error {
	if f.err != nil {
		return f.err
	}
	f.log = log
	return nil
}

func (f *fakeClinicalStore) CalculateMedicationAdherence(ctx context.Context, patientID, medicationID string) (float64, error) {
	if f.err != nil {
		return 0, f.err
	}
	if f.adherence > 0 {
		return f.adherence, nil
	}
	return 95.0, nil
}

func TestClinicalHandlers(t *testing.T) {
	store := &fakeClinicalStore{
		records:     []models.ClinicalRecord{{ID: "clin_1", PatientID: "usr_1"}},
		medications: []models.Medication{{ID: "med_1", PatientID: "usr_1"}},
		adherence:   92.5,
	}
	handler := New(store)
	ctx := authz.WithClaims(context.Background(), &security.Claims{UserID: "usr_doc", Role: models.RoleAdmin})

	recordBody := `{
		"conditions":["hypertension"],
		"allergies":["penicillin"],
		"structured_allergies":[{"allergen":"penicillin","type":"drug","severity":"severe","clinical_manifestations":["anaphylaxis"]}],
		"pathology_details":[{"condition":"Type 2 Diabetes","icd10_code":"E11.9","status":"chronic"}],
		"gynecological_history":{"menarche_age":13,"formula_gpca":"G2P2C0A0"},
		"family_history":[{"condition":"diabetes","relationship":"mother","age_onset":52}],
		"lifestyle":{"smoking_status":"never","alcohol_frequency":"occasional","physical_activity_level":"moderate","sleep_quality_score":8.5},
		"notes":"stable",
		"recorded_at":"2023-10-15T14:30:00Z"
	}`
	recordReq := httptest.NewRequest(http.MethodPost, "/v1/patients/usr_1/clinical-records", strings.NewReader(recordBody)).WithContext(ctx)
	recordReq.SetPathValue("id", "usr_1")
	recordRes := httptest.NewRecorder()
	handler.CreateClinicalRecord(recordRes, recordReq)
	if recordRes.Code != http.StatusCreated || store.record.ID == "" || store.record.RecordedBy != "usr_doc" {
		t.Fatalf("CreateClinicalRecord status=%d record=%+v", recordRes.Code, store.record)
	}
	if len(store.record.StructuredAllergies) != 1 || store.record.GynecologicalHistory == nil || store.record.Lifestyle == nil {
		t.Fatalf("CreateClinicalRecord failed to store structured subdocuments: %+v", store.record)
	}

	listRecordReq := httptest.NewRequest(http.MethodGet, "/v1/patients/usr_1/clinical-records", nil)
	listRecordReq.SetPathValue("id", "usr_1")
	listRecordRes := httptest.NewRecorder()
	handler.ListClinicalRecords(listRecordRes, listRecordReq)
	if listRecordRes.Code != http.StatusOK {
		t.Fatalf("ListClinicalRecords status=%d", listRecordRes.Code)
	}

	medReq := httptest.NewRequest(http.MethodPost, "/v1/patients/usr_1/medications", strings.NewReader(`{
		"name":"Amlodipine",
		"dosage":"5mg",
		"schedule":"daily",
		"route":"oral",
		"frequency_details":"Every morning with water",
		"complementary_therapies":["Low sodium diet"],
		"active":true
	}`))
	medReq.SetPathValue("id", "usr_1")
	medRes := httptest.NewRecorder()
	handler.CreateMedication(medRes, medReq)
	if medRes.Code != http.StatusCreated || store.medication.ID == "" || !store.medication.Active || store.medication.Route != "oral" {
		t.Fatalf("CreateMedication status=%d medication=%+v", medRes.Code, store.medication)
	}

	listMedReq := httptest.NewRequest(http.MethodGet, "/v1/patients/usr_1/medications", nil)
	listMedReq.SetPathValue("id", "usr_1")
	listMedRes := httptest.NewRecorder()
	handler.ListMedications(listMedRes, listMedReq)
	if listMedRes.Code != http.StatusOK {
		t.Fatalf("ListMedications status=%d", listMedRes.Code)
	}

	logReq := httptest.NewRequest(http.MethodPost, "/v1/patients/usr_1/medication-logs", strings.NewReader(`{"medication_id":"med_1","status":"taken","taken_at":"2023-10-15T14:30:00Z"}`))
	logReq.SetPathValue("id", "usr_1")
	logRes := httptest.NewRecorder()
	handler.RecordMedicationLog(logRes, logReq)
	if logRes.Code != http.StatusCreated || store.log.ID == "" || store.log.Status != "taken" {
		t.Fatalf("RecordMedicationLog status=%d log=%+v", logRes.Code, store.log)
	}
}

func TestClinicalHandlersRejectInvalidInput(t *testing.T) {
	handler := New(&fakeClinicalStore{})

	recordReq := httptest.NewRequest(http.MethodPost, "/v1/patients/usr_1/clinical-records", strings.NewReader(`{"conditions":[""],"allergies":[]}`))
	recordReq.SetPathValue("id", "usr_1")
	recordRes := httptest.NewRecorder()
	handler.CreateClinicalRecord(recordRes, recordReq)
	if recordRes.Code != http.StatusBadRequest {
		t.Fatalf("CreateClinicalRecord invalid status=%d", recordRes.Code)
	}

	medReq := httptest.NewRequest(http.MethodPost, "/v1/patients/usr_1/medications", strings.NewReader(`{"name":"","dosage":"5mg","schedule":"daily"}`))
	medReq.SetPathValue("id", "usr_1")
	medRes := httptest.NewRecorder()
	handler.CreateMedication(medRes, medReq)
	if medRes.Code != http.StatusBadRequest {
		t.Fatalf("CreateMedication invalid status=%d", medRes.Code)
	}

	logReq := httptest.NewRequest(http.MethodPost, "/v1/patients/usr_1/medication-logs", strings.NewReader(`{"medication_id":"med_1","status":"late"}`))
	logReq.SetPathValue("id", "usr_1")
	logRes := httptest.NewRecorder()
	handler.RecordMedicationLog(logRes, logReq)
	if logRes.Code != http.StatusBadRequest {
		t.Fatalf("RecordMedicationLog invalid status=%d", logRes.Code)
	}
}

func TestClinicalHandlersReturnStoreErrors(t *testing.T) {
	handler := New(&fakeClinicalStore{err: errors.New("store down")})
	ctx := authz.WithClaims(context.Background(), &security.Claims{UserID: "usr_doc", Role: models.RoleAdmin})

	recordReq := httptest.NewRequest(http.MethodPost, "/v1/patients/usr_1/clinical-records", strings.NewReader(`{"conditions":["hypertension"],"allergies":[]}`)).WithContext(ctx)
	recordReq.SetPathValue("id", "usr_1")
	recordRes := httptest.NewRecorder()
	handler.CreateClinicalRecord(recordRes, recordReq)
	if recordRes.Code != http.StatusInternalServerError {
		t.Fatalf("CreateClinicalRecord status=%d", recordRes.Code)
	}

	listRecordReq := httptest.NewRequest(http.MethodGet, "/v1/patients/usr_1/clinical-records", nil)
	listRecordReq.SetPathValue("id", "usr_1")
	listRecordRes := httptest.NewRecorder()
	handler.ListClinicalRecords(listRecordRes, listRecordReq)
	if listRecordRes.Code != http.StatusInternalServerError {
		t.Fatalf("ListClinicalRecords status=%d", listRecordRes.Code)
	}

	medReq := httptest.NewRequest(http.MethodPost, "/v1/patients/usr_1/medications", strings.NewReader(`{"name":"Amlodipine","dosage":"5mg","schedule":"daily"}`))
	medReq.SetPathValue("id", "usr_1")
	medRes := httptest.NewRecorder()
	handler.CreateMedication(medRes, medReq)
	if medRes.Code != http.StatusInternalServerError {
		t.Fatalf("CreateMedication status=%d", medRes.Code)
	}

	listMedReq := httptest.NewRequest(http.MethodGet, "/v1/patients/usr_1/medications", nil)
	listMedReq.SetPathValue("id", "usr_1")
	listMedRes := httptest.NewRecorder()
	handler.ListMedications(listMedRes, listMedReq)
	if listMedRes.Code != http.StatusInternalServerError {
		t.Fatalf("ListMedications status=%d", listMedRes.Code)
	}

	logReq := httptest.NewRequest(http.MethodPost, "/v1/patients/usr_1/medication-logs", strings.NewReader(`{"medication_id":"med_1","status":"taken"}`))
	logReq.SetPathValue("id", "usr_1")
	logRes := httptest.NewRecorder()
	handler.RecordMedicationLog(logRes, logReq)
	if logRes.Code != http.StatusInternalServerError {
		t.Fatalf("RecordMedicationLog status=%d", logRes.Code)
	}
}
