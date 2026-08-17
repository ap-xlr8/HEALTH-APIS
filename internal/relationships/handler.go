package relationships

import (
	"net/http"
	"strings"
	"time"

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

func (h Handler) GenerateLinkingCode(w http.ResponseWriter, r *http.Request) {
	claims, _ := authz.ClaimsFromContext(r.Context())
	if claims == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	user, err := h.store.FindUserByID(r.Context(), claims.UserID)
	name := ""
	if err == nil {
		name = user.FirstName + " " + user.LastName
		if name == " " {
			name = user.Email
		}
	}
	linkingCode, err := New(h.store).GenerateLinkingCode(r.Context(), claims.UserID, claims.Role, name)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"status": "success", "data": linkingCode})
}

func (h Handler) GetActiveLinkingCode(w http.ResponseWriter, r *http.Request) {
	claims, _ := authz.ClaimsFromContext(r.Context())
	if claims == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	linkingCode, err := New(h.store).GetActiveLinkingCode(r.Context(), claims.UserID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "data": nil})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "data": linkingCode})
}

func (h Handler) ClaimLinkingCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code   string   `json:"code"`
		Scopes []string `json:"scopes"`
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
	relationship, err := New(h.store).ClaimLinkingCode(r.Context(), req.Code, claims.UserID, claims.Role, req.Scopes)
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

	for i := range relationships {
		rel := &relationships[i]
		if rel.CaregiverID != "" {
			if cg, err := h.store.FindUserByID(r.Context(), rel.CaregiverID); err == nil {
				name := strings.TrimSpace(cg.FirstName + " " + cg.LastName)
				if name == "" {
					name = cg.Email
				}
				rel.CaregiverName = name
				rel.CaregiverEmail = cg.Email
				if cg.CaregiverProfile != nil {
					if cg.CaregiverProfile.Specialty != "" {
						rel.CaregiverRole = cg.CaregiverProfile.Specialty
					} else if cg.CaregiverProfile.ProfessionalTitle != "" {
						rel.CaregiverRole = cg.CaregiverProfile.ProfessionalTitle
					}
					rel.CaregiverPhone = cg.CaregiverProfile.Phone
				}
				if rel.CaregiverRole == "" {
					rel.CaregiverRole = "Médico / Cuidador Asignado"
				}
			}
		}

		if rel.PatientID != "" {
			if pt, err := h.store.FindUserByID(r.Context(), rel.PatientID); err == nil {
				name := strings.TrimSpace(pt.FirstName + " " + pt.LastName)
				if name == "" {
					name = pt.Email
				}
				rel.PatientName = name
				rel.PatientEmail = pt.Email
				rel.Age = pt.Age
				if rel.Age == 0 && pt.HealthProfile != nil && pt.HealthProfile.BirthDate != "" {
					if t, err := time.Parse("2006-01-02", pt.HealthProfile.BirthDate); err == nil {
						rel.Age = int(time.Since(t).Hours() / 24 / 365.25)
					}
				}
				rel.ActiveConditions = pt.ActiveConditions
				if len(rel.ActiveConditions) > 0 {
					rel.Condition = strings.Join(rel.ActiveConditions, ", ")
				} else {
					rel.Condition = "En supervisión clínica activa"
				}
				if pt.HealthProfile != nil && pt.HealthProfile.Address != "" {
					rel.Location = map[string]any{
						"address": pt.HealthProfile.Address,
					}
				}
			}
		}

		if len(rel.Scopes) == 0 {
			rel.Scopes = []string{"read:measurements", "read:alerts", "read:patient"}
		}
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{"status": "success", "data": relationships})
}
