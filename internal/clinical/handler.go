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
	CreateMedication(ctx context.Context, medication models.Medication) error
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
		FrequencyDetails:       strings.TrimSpace(req.FrequencyDetails),
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
