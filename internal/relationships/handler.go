package relationships

import (
	"net/http"

	"healthos/backend/internal/authz"
	"healthos/backend/pkg/httpx"
)

type Handler struct {
	store Store
}

func NewHandler(store Store) Handler {
	return Handler{store: store}
}

func (h Handler) AssignCaregiver(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CaregiverID string `json:"caregiver_id"`
		PatientID   string `json:"patient_id"`
		Identifier  string `json:"identifier"`
		Email       string `json:"email"`
	}
	if err := httpx.DecodeJSON(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	claims, _ := authz.ClaimsFromContext(r.Context())
	if claims == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}

	patientID := claims.UserID
	caregiverID := req.CaregiverID
	if caregiverID == "" {
		if req.Email != "" {
			caregiverID = req.Email
		} else if req.Identifier != "" {
			caregiverID = req.Identifier
		}
	}

	if claims.Role == "caregiver" {
		caregiverID = claims.UserID
		patientID = req.PatientID
		if patientID == "" {
			if req.Email != "" {
				patientID = req.Email
			} else if req.Identifier != "" {
				patientID = req.Identifier
			}
		}
	}

	relationship, err := New(h.store).AssignCaregiver(r.Context(), patientID, caregiverID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"status": "success", "data": relationship})
}

func (h Handler) RevokeCaregiver(w http.ResponseWriter, r *http.Request) {
	claims, _ := authz.ClaimsFromContext(r.Context())
	relationship, err := New(h.store).RevokeCaregiver(r.Context(), claims.UserID, r.PathValue("caregiver_id"))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "data": relationship})
}

func (h Handler) List(w http.ResponseWriter, r *http.Request) {
	claims, _ := authz.ClaimsFromContext(r.Context())
	relationships, err := h.store.ListRelationshipsForUser(r.Context(), claims.UserID, claims.Role)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "could not list relationships")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "data": relationships})
}
