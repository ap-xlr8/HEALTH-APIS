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

func (h Handler) UpdateHealthProfile(w http.ResponseWriter, r *http.Request) {
	claims, ok := authz.ClaimsFromContext(r.Context())
	if !ok || claims == nil || claims.UserID == "" {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	var req healthProfileRequest
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}

	bloodType := strings.ToUpper(strings.TrimSpace(req.BloodType))
	if req.WeightKg < 20 || req.WeightKg > 300 {
		httpx.WriteError(w, http.StatusBadRequest, "weight_kg must be between 20 and 300")
		return
	}
	if req.HeightCm < 50 || req.HeightCm > 250 {
		httpx.WriteError(w, http.StatusBadRequest, "height_cm must be between 50 and 250")
		return
	}
	if !validBloodTypes[bloodType] {
		httpx.WriteError(w, http.StatusBadRequest, "blood_type must be one of A+, A-, B+, B-, AB+, AB-, O+, O-")
		return
	}

	profile := models.HealthProfile{
		WeightKg:         req.WeightKg,
		HeightCm:         req.HeightCm,
		BloodType:        bloodType,
		RhFactor:         strings.TrimSpace(req.RhFactor),
		BirthDate:        strings.TrimSpace(req.BirthDate),
		BiologicalSex:    strings.ToLower(strings.TrimSpace(req.BiologicalSex)),
		Phone:            strings.TrimSpace(req.Phone),
		Address:          strings.TrimSpace(req.Address),
		EmergencyContact: req.EmergencyContact,
		BaselineVitals:   req.BaselineVitals,
	}

	if err := h.store.UpdateUserHealthProfile(r.Context(), claims.UserID, profile); err != nil {
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
