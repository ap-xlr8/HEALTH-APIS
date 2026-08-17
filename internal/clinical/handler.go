package clinical

import (
	"context"
	"net/http"
	"strings"
	"time"

	"healthos/backend/internal/authz"
	"healthos/backend/internal/models"
	"healthos/backend/pkg/httpx"
)

type Store interface {
	CreateClinicalRecord(ctx context.Context, record models.ClinicalRecord) error
	ListClinicalRecords(ctx context.Context, patientID string) ([]models.ClinicalRecord, error)
	CreatePrescription(ctx context.Context, prescription models.Prescription) error
	ListPrescriptions(ctx context.Context, patientID string) ([]models.Prescription, error)
	CreateMedication(ctx context.Context, medication models.Medication) error
	UpdateMedicationStatus(ctx context.Context, patientID, medicationID, status string, active bool) error
	DeleteMedication(ctx context.Context, patientID, medicationID string) error
	ListMedications(ctx context.Context, patientID string) ([]models.Medication, error)
	RecordMedicationLog(ctx context.Context, log models.MedicationLog) error
	CalculateMedicationAdherence(ctx context.Context, patientID, medicationID string) (float64, error)
}

type Handler struct {
	store Store
}

func New(store Store) Handler {
	return Handler{store: store}
}

type clinicalRecordRequest struct {
	Conditions           []string                       `json:"conditions,omitempty"`
	Allergies            []string                       `json:"allergies,omitempty"`
	StructuredAllergies  []models.Allergy               `json:"structured_allergies,omitempty"`
	PathologyDetails     []models.PathologicalCondition `json:"pathology_details,omitempty"`
	GynecologicalHistory *models.GynecologicalHistory   `json:"gynecological_history,omitempty"`
	FamilyHistory        []models.FamilyHistoryItem     `json:"family_history,omitempty"`
	Lifestyle            *models.Lifestyle              `json:"lifestyle,omitempty"`
	Notes                string                         `json:"notes,omitempty"`
	RecordedAt           string                         `json:"recorded_at,omitempty"`
}

func (h Handler) CreateClinicalRecord(w http.ResponseWriter, r *http.Request) {
	patientID := r.PathValue("id")
	var req clinicalRecordRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}

	conditions, ok := cleanList(req.Conditions, 50, 80)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "conditions contains invalid values")
		return
	}
	allergies, ok := cleanList(req.Allergies, 50, 80)
	if !ok {
		httpx.WriteError(w, http.StatusBadRequest, "allergies contains invalid values")
		return
	}

	// Also extract conditions from pathology details if not explicitly passed
	if len(conditions) == 0 && len(req.PathologyDetails) > 0 {
		for _, pd := range req.PathologyDetails {
			if cond := strings.TrimSpace(pd.Condition); cond != "" {
				conditions = append(conditions, cond)
			}
		}
	}

	// Also extract allergen names from structured allergies if not explicitly passed
	if len(allergies) == 0 && len(req.StructuredAllergies) > 0 {
		for _, sa := range req.StructuredAllergies {
			if allergen := strings.TrimSpace(sa.Allergen); allergen != "" {
				allergies = append(allergies, allergen)
			}
		}
	}

	notes := strings.TrimSpace(req.Notes)
	if len(notes) > 2000 {
		httpx.WriteError(w, http.StatusBadRequest, "notes must be <= 2000 characters")
		return
	}
	recordedAt := time.Now().UTC()
	if strings.TrimSpace(req.RecordedAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(req.RecordedAt))
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "recorded_at must be RFC3339")
			return
		}
		recordedAt = parsed.UTC()
	}
	claims, _ := authz.ClaimsFromContext(r.Context())
	now := time.Now().UTC()
	id := randomID()
	if id == "" {
		httpx.WriteError(w, http.StatusInternalServerError, "secure id generation failed")
		return
	}

	record := models.ClinicalRecord{
		ID:                   "clin_" + id,
		PatientID:            patientID,
		Conditions:           conditions,
		Allergies:            allergies,
		StructuredAllergies:  req.StructuredAllergies,
		PathologyDetails:     req.PathologyDetails,
		GynecologicalHistory: req.GynecologicalHistory,
		FamilyHistory:        req.FamilyHistory,
		Lifestyle:            req.Lifestyle,
		Notes:                notes,
		RecordedBy:           claims.UserID,
		RecordedAt:           recordedAt,
		CreatedAt:            now,
	}
	if err := h.store.CreateClinicalRecord(r.Context(), record); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create clinical record")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"status": "success", "data": record})
}

func (h Handler) ListClinicalRecords(w http.ResponseWriter, r *http.Request) {
	records, err := h.store.ListClinicalRecords(r.Context(), r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list clinical records")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "data": records})
}

func (h Handler) CreateMedication(w http.ResponseWriter, r *http.Request) {
	patientID := r.PathValue("id")
	var req struct {
		Name                   string   `json:"name"`
		Dosage                 string   `json:"dosage"`
		Schedule               string   `json:"schedule"`
		Route                  string   `json:"route,omitempty"`
		FrequencyDetails       string   `json:"frequency_details,omitempty"`
		Instructions           string   `json:"instructions,omitempty"`
		PrescribedBy           string   `json:"prescribed_by,omitempty"`
		StartDate              string   `json:"start_date,omitempty"`
		EndDate                string   `json:"end_date,omitempty"`
		DurationDays           int      `json:"duration_days,omitempty"`
		IsIndefinite           bool     `json:"is_indefinite,omitempty"`
		Status                 string   `json:"status,omitempty"`
		ComplementaryTherapies []string `json:"complementary_therapies,omitempty"`
		Active                 *bool    `json:"active"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	name, dosage, schedule := strings.TrimSpace(req.Name), strings.TrimSpace(req.Dosage), strings.TrimSpace(req.Schedule)
	if name == "" || len(name) > 120 || dosage == "" || len(dosage) > 80 || schedule == "" || len(schedule) > 200 {
		httpx.WriteError(w, http.StatusBadRequest, "name, dosage and schedule are required")
		return
	}
	active := true
	if req.Active != nil {
		active = *req.Active
	}
	status := "active"
	if req.Status != "" {
		status = req.Status
	} else if !active {
		status = "completed"
	}

	instructions := strings.TrimSpace(req.Instructions)
	if instructions == "" {
		instructions = strings.TrimSpace(req.FrequencyDetails)
	}

	now := time.Now().UTC()
	id := randomID()
	if id == "" {
		httpx.WriteError(w, http.StatusInternalServerError, "secure id generation failed")
		return
	}
	medication := models.Medication{
		ID:                     "med_" + id,
		PatientID:              patientID,
		Name:                   name,
		Dosage:                 dosage,
		Schedule:               schedule,
		Route:                  strings.TrimSpace(req.Route),
		FrequencyDetails:       instructions,
		Instructions:           instructions,
		PrescribedBy:           strings.TrimSpace(req.PrescribedBy),
		StartDate:              strings.TrimSpace(req.StartDate),
		EndDate:                strings.TrimSpace(req.EndDate),
		DurationDays:           req.DurationDays,
		IsIndefinite:           req.IsIndefinite,
		Status:                 status,
		ComplementaryTherapies: req.ComplementaryTherapies,
		Active:                 active,
		CalculatedAdherence:    100.0,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if err := h.store.CreateMedication(r.Context(), medication); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not create medication")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"status": "success", "data": medication})
}

func (h Handler) UpdateMedicationStatus(w http.ResponseWriter, r *http.Request) {
	patientID := r.PathValue("id")
	medicationID := r.PathValue("med_id")
	if patientID == "" || medicationID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "patient id and medication id are required")
		return
	}
	var req struct {
		Status string `json:"status"`
		Active *bool  `json:"active"`
	}
	_ = httpx.DecodeJSON(r, &req)
	status := strings.TrimSpace(req.Status)
	if status == "" {
		status = "completed"
	}
	active := false
	if req.Active != nil {
		active = *req.Active
	} else if status == "active" {
		active = true
	}
	if err := h.store.UpdateMedicationStatus(r.Context(), patientID, medicationID, status, active); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not update medication status")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "message": "medication status updated"})
}

func (h Handler) DeleteMedication(w http.ResponseWriter, r *http.Request) {
	patientID := r.PathValue("id")
	medicationID := r.PathValue("med_id")
	if patientID == "" || medicationID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "patient id and medication id are required")
		return
	}
	if err := h.store.DeleteMedication(r.Context(), patientID, medicationID); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not delete medication")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "message": "medication deleted"})
}

func (h Handler) ListMedications(w http.ResponseWriter, r *http.Request) {
	patientID := r.PathValue("id")
	medications, err := h.store.ListMedications(r.Context(), patientID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list medications")
		return
	}
	// Calculate dynamic adherence for each medication
	for i := range medications {
		if adherence, err := h.store.CalculateMedicationAdherence(r.Context(), patientID, medications[i].ID); err == nil {
			medications[i].CalculatedAdherence = adherence
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "data": medications})
}

func (h Handler) RecordMedicationLog(w http.ResponseWriter, r *http.Request) {
	patientID := r.PathValue("id")
	var req struct {
		MedicationID string `json:"medication_id"`
		Status       string `json:"status"`
		TakenAt      string `json:"taken_at"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	medicationID, status := strings.TrimSpace(req.MedicationID), strings.TrimSpace(req.Status)
	if medicationID == "" || len(medicationID) > 80 || !allowed(status, "taken", "missed", "skipped") {
		httpx.WriteError(w, http.StatusBadRequest, "medication_id and valid status are required")
		return
	}
	takenAt := time.Now().UTC()
	if strings.TrimSpace(req.TakenAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(req.TakenAt))
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "taken_at must be RFC3339")
			return
		}
		takenAt = parsed.UTC()
	}
	id := randomID()
	if id == "" {
		httpx.WriteError(w, http.StatusInternalServerError, "secure id generation failed")
		return
	}
	log := models.MedicationLog{
		ID:           "mlog_" + id,
		PatientID:    patientID,
		MedicationID: medicationID,
		Status:       status,
		TakenAt:      takenAt,
		CreatedAt:    time.Now().UTC(),
	}
	if err := h.store.RecordMedicationLog(r.Context(), log); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not record medication log")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"status": "success", "data": log})
}

func (h Handler) CreatePrescription(w http.ResponseWriter, r *http.Request) {
	patientID := r.PathValue("id")
	if patientID == "" || patientID == "me" {
		if claims, ok := authz.ClaimsFromContext(r.Context()); ok && claims != nil {
			patientID = claims.UserID
		}
	}
	if patientID == "" || len(patientID) > 80 {
		httpx.WriteError(w, http.StatusBadRequest, "patient id is required")
		return
	}

	var req struct {
		ConsultationDate string                    `json:"consultation_date"`
		Diagnosis        string                    `json:"diagnosis"`
		DoctorName       string                    `json:"doctor_name"`
		Institution      string                    `json:"institution"`
		Notes            string                    `json:"notes"`
		Medications      []models.PrescriptionItem `json:"medications"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}

	diagnosis := strings.TrimSpace(req.Diagnosis)
	if diagnosis == "" {
		httpx.WriteError(w, http.StatusBadRequest, "diagnosis is required")
		return
	}
	doctorName := strings.TrimSpace(req.DoctorName)
	if doctorName == "" {
		doctorName = "Médico tratante"
	}
	consultationDate := strings.TrimSpace(req.ConsultationDate)
	if consultationDate == "" {
		consultationDate = time.Now().UTC().Format("2006-01-02")
	}

	claims, _ := authz.ClaimsFromContext(r.Context())
	creatorID := patientID
	if claims != nil && claims.UserID != "" {
		creatorID = claims.UserID
	}

	now := time.Now().UTC()
	prescID := "rx_" + randomID()
	if prescID == "rx_" {
		prescID = "rx_" + time.Now().Format("20060102150405")
	}

	prescription := models.Prescription{
		ID:               prescID,
		PatientID:        patientID,
		ConsultationDate: consultationDate,
		Diagnosis:        diagnosis,
		DoctorName:       doctorName,
		Institution:      strings.TrimSpace(req.Institution),
		Notes:            strings.TrimSpace(req.Notes),
		Medications:      req.Medications,
		CreatedBy:        creatorID,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := h.store.CreatePrescription(r.Context(), prescription); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to save prescription")
		return
	}

	// Automatically insert each linked medication into medications collection
	for _, medItem := range req.Medications {
		name := strings.TrimSpace(medItem.Name)
		if name == "" {
			continue
		}
		dose := strings.TrimSpace(medItem.Dose)
		if dose == "" {
			dose = "1 dosis"
		}
		freq := strings.TrimSpace(medItem.Frequency)
		if freq == "" {
			freq = "Según indicación médica"
		}
		medID := "med_" + randomID()
		if medID == "med_" {
			medID = "med_" + time.Now().Format("20060102150405")
		}

		med := models.Medication{
			ID:               medID,
			PatientID:        patientID,
			Name:             name,
			Dosage:           dose,
			Schedule:         freq,
			Route:            strings.TrimSpace(medItem.Route),
			FrequencyDetails: freq,
			Instructions:     strings.TrimSpace(medItem.Instructions),
			PrescribedBy:     doctorName,
			StartDate:        consultationDate,
			DurationDays:     medItem.DurationDays,
			Status:           "active",
			Active:           true,
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		_ = h.store.CreateMedication(r.Context(), med)
	}

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"status":  "success",
		"message": "prescription and linked medications registered successfully",
		"data":    prescription,
	})
}

func (h Handler) ListPrescriptions(w http.ResponseWriter, r *http.Request) {
	patientID := r.PathValue("id")
	if patientID == "" || patientID == "me" {
		if claims, ok := authz.ClaimsFromContext(r.Context()); ok && claims != nil {
			patientID = claims.UserID
		}
	}
	if patientID == "" || len(patientID) > 80 {
		httpx.WriteError(w, http.StatusBadRequest, "patient id is required")
		return
	}

	prescriptions, err := h.store.ListPrescriptions(r.Context(), patientID)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to list prescriptions")
		return
	}
	if prescriptions == nil {
		prescriptions = []models.Prescription{}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"data":   prescriptions,
	})
}
