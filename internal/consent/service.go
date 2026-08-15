package consent

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"healthos/backend/internal/models"
)

type Store interface {
	UpsertConsent(ctx context.Context, consent models.Consent) error
}

type Broadcaster interface {
	Broadcast(payload any)
}

type Service struct {
	store       Store
	broadcaster Broadcaster
}

func New(store Store, broadcaster Broadcaster) Service {
	return Service{store: store, broadcaster: broadcaster}
}

func (s Service) Grant(ctx context.Context, patientID, caregiverID string, scopes []string) (models.Consent, error) {
	patientID, caregiverID = cleanPair(patientID, caregiverID)
	if err := validatePair(patientID, caregiverID); err != nil {
		return models.Consent{}, err
	}
	normalizedScopes, err := normalizeScopes(scopes)
	if err != nil {
		return models.Consent{}, err
	}
	now := time.Now().UTC()
	consent := models.Consent{
		ID:          "con_" + uuid.NewString(),
		PatientID:   patientID,
		CaregiverID: caregiverID,
		Scopes:      normalizedScopes,
		Revoked:     false,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.store.UpsertConsent(ctx, consent); err != nil {
		return models.Consent{}, err
	}
	s.broadcast(map[string]any{
		"type":        "consent.updated",
		"patientId":   consent.PatientID,
		"caregiverId": consent.CaregiverID,
		"scopes":      consent.Scopes,
		"updatedAt":   consent.UpdatedAt,
		"eventId":     "evt_" + uuid.NewString(),
	})
	return consent, nil
}

func (s Service) Revoke(ctx context.Context, patientID, caregiverID string) (models.Consent, error) {
	patientID, caregiverID = cleanPair(patientID, caregiverID)
	if err := validatePair(patientID, caregiverID); err != nil {
		return models.Consent{}, err
	}
	now := time.Now().UTC()
	consent := models.Consent{
		ID:          "con_" + uuid.NewString(),
		PatientID:   patientID,
		CaregiverID: caregiverID,
		Scopes:      []string{},
		Revoked:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.store.UpsertConsent(ctx, consent); err != nil {
		return models.Consent{}, err
	}
	s.broadcast(map[string]any{
		"type":        "consent.updated",
		"patientId":   consent.PatientID,
		"caregiverId": consent.CaregiverID,
		"scopes":      consent.Scopes,
		"updatedAt":   consent.UpdatedAt,
		"eventId":     "evt_" + uuid.NewString(),
	})
	return consent, nil
}

func (s Service) broadcast(payload any) {
	if s.broadcaster != nil {
		s.broadcaster.Broadcast(payload)
	}
}

func cleanPair(patientID, caregiverID string) (string, string) {
	return strings.TrimSpace(patientID), strings.TrimSpace(caregiverID)
}

func validatePair(patientID, caregiverID string) error {
	if patientID == "" || caregiverID == "" {
		return errors.New("patient_id and caregiver_id are required")
	}
	if len(patientID) > 80 || len(caregiverID) > 80 {
		return errors.New("patient_id and caregiver_id must be <= 80 characters")
	}
	if patientID == caregiverID {
		return errors.New("consent requires different patient and caregiver users")
	}
	return nil
}

func normalizeScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, errors.New("at least one consent scope is required")
	}
	allowedScopes := []string{models.ScopeReadAlerts, models.ScopeReadMeasurements, models.ScopeReadPatient}
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if !slices.Contains(allowedScopes, scope) {
			return nil, errors.New("unsupported consent scope")
		}
		if !slices.Contains(out, scope) {
			out = append(out, scope)
		}
	}
	slices.Sort(out)
	return out, nil
}
