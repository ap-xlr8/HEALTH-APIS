package patients

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"healthos/backend/internal/authz"
	"healthos/backend/internal/models"
	"healthos/backend/internal/store"
	"healthos/backend/pkg/httpx"
)

type Store interface {
	FindUserByID(ctx context.Context, id string) (models.User, error)
	UpdateUserHealthProfile(ctx context.Context, userID string, profile models.HealthProfile) error
	ListMedications(ctx context.Context, patientID string) ([]models.Medication, error)
}

type Handler struct {
	store Store
}

func New(store Store) Handler {
	return Handler{store: store}
}

type healthProfileRequest struct {
	WeightKg         float64                  `json:"weight_kg"`
	HeightCm         int                      `json:"height_cm"`
	BloodType        string                   `json:"blood_type"`
	RhFactor         string                   `json:"rh_factor,omitempty"`
	BirthDate        string                   `json:"birth_date,omitempty"`
	BiologicalSex    string                   `json:"biological_sex,omitempty"`
	Phone            string                   `json:"phone,omitempty"`
	Address          string                   `json:"address,omitempty"`
	EmergencyContact *models.EmergencyContact `json:"emergency_contact,omitempty"`
	BaselineVitals   *models.BaselineVitals   `json:"baseline_vitals,omitempty"`
}

var validBloodTypes = map[string]bool{
	"A+": true, "A-": true, "B+": true, "B-": true,
	"AB+": true, "AB-": true, "O+": true, "O-": true,
	"A": true, "B": true, "AB": true, "O": true, "": true,
}

func (h Handler) GetPatient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || len(id) > 80 {
		httpx.WriteError(w, http.StatusBadRequest, "patient id is required")
		return
	}
	user, err := h.store.FindUserByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "patient not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "patient lookup failed")
		return
	}
	if user.Role != models.RolePatient {
		httpx.WriteError(w, http.StatusNotFound, "patient not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id":                user.ID,
		"first_name":        user.FirstName,
		"last_name":         user.LastName,
		"age":               user.Age,
		"health_profile":    user.HealthProfile,
		"active_conditions": user.ActiveConditions,
	})
}

func (h Handler) GetHealthProfile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || id == "me" {
		if claims, ok := authz.ClaimsFromContext(r.Context()); ok && claims != nil {
			id = claims.UserID
		}
	}
	if id == "" || len(id) > 80 {
		httpx.WriteError(w, http.StatusBadRequest, "patient id is required")
		return
	}
	user, err := h.store.FindUserByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "patient not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "patient lookup failed")
		return
	}
	if user.Role != models.RolePatient {
		httpx.WriteError(w, http.StatusNotFound, "patient not found")
		return
	}

	meds, err := h.store.ListMedications(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "medications lookup failed")
		return
	}
	if meds == nil {
		meds = make([]models.Medication, 0)
	}

	hp := user.HealthProfile
	if hp == nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"patientId": user.ID,
			"basalProfile": map[string]any{
				"bloodType":               "",
				"rhFactor":                "",
				"weightKg":                0,
				"heightCm":                0,
				"bmi":                     0,
				"bmiCategory":             "Sin calcular",
				"primaryEmergencyContact": map[string]string{"name": "", "phone": "", "relation": ""},
				"updatedAt":               user.CreatedAt.Format("2006-01-02"),
			},
			"allergies":   []any{},
			"medications": meds,
			"pathological": map[string]any{
				"chronicDiseases":  []any{},
				"surgeries":        []any{},
				"hospitalizations": []any{},
				"implants":         []any{},
				"transfusions":     []any{},
			},
			"gynecological": map[string]any{"applicable": false},
			"familyHistory": []any{},
			"lifestyle": map[string]any{
				"tobacco":          map[string]any{"status": "never", "packYears": 0, "cigarettesPerDay": 0},
				"alcohol":          map[string]any{"frequency": "never", "unitsPerWeek": 0},
				"physicalActivity": map[string]any{"level": "moderate", "daysPerWeek": 0, "minutesPerSession": 0, "activityTypes": ""},
				"sleep":            map[string]any{"averageHours": 0, "quality": "good"},
				"dietType":         "balanced",
			},
		})
		return
	}

	// Calculate BMI if weight and height are present
	bmi := 0.0
	bmiCategory := "Sin calcular"
	if hp.WeightKg > 0 && hp.HeightCm > 0 {
		hM := float64(hp.HeightCm) / 100.0
		bmi = hp.WeightKg / (hM * hM)
		if bmi < 18.5 {
			bmiCategory = "underweight"
		} else if bmi < 25 {
			bmiCategory = "normal"
		} else if bmi < 30 {
			bmiCategory = "overweight"
		} else {
			bmiCategory = "obesity"
		}
	}

	emergencyContact := map[string]string{"name": "", "phone": "", "relation": ""}
	if hp.EmergencyContact != nil {
		emergencyContact["name"] = hp.EmergencyContact.Name
		emergencyContact["phone"] = hp.EmergencyContact.Phone
		emergencyContact["relation"] = hp.EmergencyContact.Relationship
	}

	basalProfile := map[string]any{
		"bloodType":               hp.BloodType,
		"rhFactor":                hp.RhFactor,
		"weightKg":                hp.WeightKg,
		"heightCm":                hp.HeightCm,
		"bmi":                     bmi,
		"bmiCategory":             bmiCategory,
		"primaryEmergencyContact": emergencyContact,
		"updatedAt":               user.CreatedAt.Format("2006-01-02"),
	}
	if hp.BasalProfile != nil {
		for k, v := range hp.BasalProfile {
			basalProfile[k] = v
		}
	}

	allergies := hp.Allergies
	if allergies == nil {
		allergies = make([]any, 0)
	}

	pathological := hp.Pathological
	if pathological == nil {
		pathological = map[string]any{
			"chronicDiseases":  []any{},
			"surgeries":        []any{},
			"hospitalizations": []any{},
			"implants":         []any{},
			"transfusions":     []any{},
		}
	}

	gynecological := hp.Gynecological
	if gynecological == nil {
		gynecological = map[string]any{"applicable": false}
	}

	familyHistory := hp.FamilyHistory
	if familyHistory == nil {
		familyHistory = make([]any, 0)
	}

	lifestyle := hp.Lifestyle
	if lifestyle == nil {
		lifestyle = map[string]any{
			"tobacco":          map[string]any{"status": "never", "packYears": 0, "cigarettesPerDay": 0},
			"alcohol":          map[string]any{"frequency": "never", "unitsPerWeek": 0},
			"physicalActivity": map[string]any{"level": "moderate", "daysPerWeek": 0, "minutesPerSession": 0, "activityTypes": ""},
			"sleep":            map[string]any{"averageHours": 0, "quality": "good"},
			"dietType":         "balanced",
		}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"patientId":     user.ID,
		"basalProfile":  basalProfile,
		"allergies":     allergies,
		"medications":   meds,
		"pathological":  pathological,
		"gynecological": gynecological,
		"familyHistory": familyHistory,
		"lifestyle":     lifestyle,
	})
}

func (h Handler) UpdateHealthProfile(w http.ResponseWriter, r *http.Request) {
	claims, ok := authz.ClaimsFromContext(r.Context())
	if !ok || claims == nil || claims.UserID == "" {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	targetUserID := claims.UserID
	if pathID := r.PathValue("id"); pathID != "" && pathID != "me" && claims.Role == models.RoleAdmin {
		targetUserID = pathID
	}

	var rawMap map[string]any
	if err := httpx.DecodeJSON(r, &rawMap); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}

	if weightVal, ok := rawMap["weight_kg"].(float64); ok && (weightVal < 20 || weightVal > 300) {
		httpx.WriteError(w, http.StatusBadRequest, "weight_kg must be between 20 and 300")
		return
	}
	if heightVal, ok := rawMap["height_cm"].(float64); ok && (heightVal < 50 || heightVal > 250) {
		httpx.WriteError(w, http.StatusBadRequest, "height_cm must be between 50 and 250")
		return
	}
	if bt, ok := rawMap["blood_type"].(string); ok && bt != "" {
		btUpper := strings.ToUpper(strings.TrimSpace(bt))
		if !validBloodTypes[btUpper] || btUpper == "" {
			httpx.WriteError(w, http.StatusBadRequest, "blood_type must be one of A+, A-, B+, B-, AB+, AB-, O+, O-")
			return
		}
	}

	// Fetch existing profile to merge partially updated sections
	existingUser, err := h.store.FindUserByID(r.Context(), targetUserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "patient not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "patient lookup failed")
		return
	}
	var profile models.HealthProfile
	if existingUser.HealthProfile != nil {
		profile = *existingUser.HealthProfile
	}

	// 1. Basal Profile / Anthropometrics
	if bp, ok := rawMap["basalProfile"].(map[string]any); ok {
		profile.BasalProfile = bp
		if w, ok := bp["weightKg"].(float64); ok && w > 0 {
			profile.WeightKg = w
		}
		if h, ok := bp["heightCm"].(float64); ok && h > 0 {
			profile.HeightCm = int(h)
		}
		if bt, ok := bp["bloodType"].(string); ok && bt != "" {
			profile.BloodType = strings.ToUpper(bt)
		}
		if rh, ok := bp["rhFactor"].(string); ok && rh != "" {
			profile.RhFactor = rh
		}
		if ec, ok := bp["primaryEmergencyContact"].(map[string]any); ok {
			name, _ := ec["name"].(string)
			phoneNum, _ := ec["phone"].(string)
			rel, _ := ec["relation"].(string)
			if rel == "" {
				rel, _ = ec["relationship"].(string)
			}
			profile.EmergencyContact = &models.EmergencyContact{
				Name:         name,
				Phone:        phoneNum,
				Relationship: rel,
			}
		}
	}
	if w, ok := rawMap["weight_kg"].(float64); ok && w > 0 {
		profile.WeightKg = w
	}
	if h, ok := rawMap["height_cm"].(float64); ok && h > 0 {
		profile.HeightCm = int(h)
	}
	if bt, ok := rawMap["blood_type"].(string); ok && bt != "" {
		profile.BloodType = strings.ToUpper(bt)
	}
	if rh, ok := rawMap["rh_factor"].(string); ok && rh != "" {
		profile.RhFactor = rh
	}
	if bd, ok := rawMap["birth_date"].(string); ok {
		profile.BirthDate = bd
	}
	if bs, ok := rawMap["biological_sex"].(string); ok {
		profile.BiologicalSex = bs
	}
	if ph, ok := rawMap["phone"].(string); ok {
		profile.Phone = ph
	}
	if addr, ok := rawMap["address"].(string); ok {
		profile.Address = addr
	}
	if ec, ok := rawMap["emergency_contact"].(map[string]any); ok {
		name, _ := ec["name"].(string)
		phoneNum, _ := ec["phone"].(string)
		rel, _ := ec["relationship"].(string)
		if rel == "" {
			rel, _ = ec["relation"].(string)
		}
		profile.EmergencyContact = &models.EmergencyContact{
			Name:         name,
			Phone:        phoneNum,
			Relationship: rel,
		}
	}

	// 2. Allergies
	if algs, ok := rawMap["allergies"].([]any); ok {
		profile.Allergies = algs
	}

	// 3. Pathological History
	if path, ok := rawMap["pathological"].(map[string]any); ok {
		profile.Pathological = path
	}

	// 4. Gynecological History
	if gyn, ok := rawMap["gynecological"].(map[string]any); ok {
		profile.Gynecological = gyn
	}

	// 5. Family History
	if fh, ok := rawMap["familyHistory"].([]any); ok {
		profile.FamilyHistory = fh
	} else if fh, ok := rawMap["family_history"].([]any); ok {
		profile.FamilyHistory = fh
	}

	// 6. Lifestyle Habits
	if lf, ok := rawMap["lifestyle"].(map[string]any); ok {
		profile.Lifestyle = lf
	}

	if err := h.store.UpdateUserHealthProfile(r.Context(), targetUserID, profile); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "patient not found")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "failed to update health profile")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"data":   profile,
	})
}
