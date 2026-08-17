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

	hp := user.HealthProfile
	var basal models.HealthProfile
	if hp != nil {
		basal = *hp
	}
	if basal.BloodType == "" {
		basal.BloodType = "O"
	}
	if basal.RhFactor == "" {
		basal.RhFactor = "+"
	}
	if basal.WeightKg == 0 {
		basal.WeightKg = 70
	}
	if basal.HeightCm == 0 {
		basal.HeightCm = 170
	}

	bmi := 22.5
	if basal.HeightCm > 0 {
		hM := float64(basal.HeightCm) / 100.0
		bmi = basal.WeightKg / (hM * hM)
	}

	emergencyContact := map[string]string{"name": "", "phone": "", "relation": ""}
	if basal.EmergencyContact != nil {
		emergencyContact["name"] = basal.EmergencyContact.Name
		emergencyContact["phone"] = basal.EmergencyContact.Phone
		emergencyContact["relation"] = basal.EmergencyContact.Relationship
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"patientId": user.ID,
		"basalProfile": map[string]any{
			"bloodType":                basal.BloodType,
			"rhFactor":                 basal.RhFactor,
			"weightKg":                 basal.WeightKg,
			"heightCm":                 basal.HeightCm,
			"bmi":                      bmi,
			"bmiCategory":              "normal",
			"primaryEmergencyContact":  emergencyContact,
			"updatedAt":                user.CreatedAt.Format("2006-01-02"),
		},
		"allergies": []any{},
		"medications": []any{},
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
			"tobacco":          map[string]any{"status": "never"},
			"alcohol":          map[string]any{"frequency": "never"},
			"physicalActivity": map[string]any{"level": "moderate", "daysPerWeek": 3, "minutesPerSession": 30},
			"sleep":            map[string]any{"averageHours": 7.5, "quality": "good"},
			"dietType":         "balanced",
		},
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

	weightKg := 70.0
	heightCm := 170
	bloodType := "O+"
	rhFactor := "+"
	birthDate := ""
	biologicalSex := ""
	phone := ""
	address := ""
	var emergencyContact *models.EmergencyContact
	var baselineVitals *models.BaselineVitals

	// Check if body is wrapped in basalProfile
	if bp, ok := rawMap["basalProfile"].(map[string]any); ok {
		if w, ok := bp["weightKg"].(float64); ok && w > 0 {
			weightKg = w
		}
		if h, ok := bp["heightCm"].(float64); ok && h > 0 {
			heightCm = int(h)
		}
		if bt, ok := bp["bloodType"].(string); ok && bt != "" {
			bloodType = strings.ToUpper(bt)
		}
		if rh, ok := bp["rhFactor"].(string); ok && rh != "" {
			rhFactor = rh
		}
		if ec, ok := bp["primaryEmergencyContact"].(map[string]any); ok {
			name, _ := ec["name"].(string)
			phoneNum, _ := ec["phone"].(string)
			rel, _ := ec["relation"].(string)
			emergencyContact = &models.EmergencyContact{
				Name:         name,
				Phone:        phoneNum,
				Relationship: rel,
			}
		}
	} else {
		if w, ok := rawMap["weight_kg"].(float64); ok && w > 0 {
			weightKg = w
		}
		if h, ok := rawMap["height_cm"].(float64); ok && h > 0 {
			heightCm = int(h)
		}
		if bt, ok := rawMap["blood_type"].(string); ok && bt != "" {
			bloodType = strings.ToUpper(bt)
		}
		if rh, ok := rawMap["rh_factor"].(string); ok && rh != "" {
			rhFactor = rh
		}
		if bd, ok := rawMap["birth_date"].(string); ok {
			birthDate = bd
		}
		if bs, ok := rawMap["biological_sex"].(string); ok {
			biologicalSex = bs
		}
		if ph, ok := rawMap["phone"].(string); ok {
			phone = ph
		}
		if addr, ok := rawMap["address"].(string); ok {
			address = addr
		}
	}

	if weightKg < 20 || weightKg > 300 {
		httpx.WriteError(w, http.StatusBadRequest, "weight_kg must be between 20 and 300")
		return
	}
	if heightCm < 50 || heightCm > 250 {
		httpx.WriteError(w, http.StatusBadRequest, "height_cm must be between 50 and 250")
		return
	}
	if !validBloodTypes[bloodType] {
		httpx.WriteError(w, http.StatusBadRequest, "blood_type must be one of A+, A-, B+, B-, AB+, AB-, O+, O-")
		return
	}

	profile := models.HealthProfile{
		WeightKg:         weightKg,
		HeightCm:         heightCm,
		BloodType:        bloodType,
		RhFactor:         rhFactor,
		BirthDate:        birthDate,
		BiologicalSex:    biologicalSex,
		Phone:            phone,
		Address:          address,
		EmergencyContact: emergencyContact,
		BaselineVitals:   baselineVitals,
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
