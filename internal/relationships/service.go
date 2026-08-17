package relationships

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"healthos/backend/internal/models"
)

type Store interface {
	UpsertRelationship(ctx context.Context, relationship models.Relationship) error
	ListRelationshipsForUser(ctx context.Context, userID, role string) ([]models.Relationship, error)
	FindUserByEmail(ctx context.Context, email string) (models.User, error)
	FindUserByID(ctx context.Context, id string) (models.User, error)
}

type Service struct {
	store Store
}

func New(store Store) Service {
	return Service{store: store}
}

func (s Service) AssignCaregiver(ctx context.Context, patientID, caregiverID string) (models.Relationship, error) {
	patientID = strings.TrimSpace(patientID)
	caregiverID = strings.TrimSpace(caregiverID)
	if patientID == "" || caregiverID == "" {
		return models.Relationship{}, errors.New("patient_id and caregiver_id are required")
	}

	// Resolve email if provided for patientID
	if strings.Contains(patientID, "@") {
		u, err := s.store.FindUserByEmail(ctx, strings.ToLower(patientID))
		if err == nil && u.ID != "" {
			patientID = u.ID
		} else {
			return models.Relationship{}, errors.New("no se encontró ningún paciente con ese correo electrónico")
		}
	}

	// Resolve email if provided for caregiverID
	if strings.Contains(caregiverID, "@") {
		u, err := s.store.FindUserByEmail(ctx, strings.ToLower(caregiverID))
		if err == nil && u.ID != "" {
			caregiverID = u.ID
		} else {
			return models.Relationship{}, errors.New("no se encontró ningún cuidador o médico con ese correo electrónico")
		}
	}

	if len(patientID) > 80 || len(caregiverID) > 80 {
		return models.Relationship{}, errors.New("patient_id and caregiver_id must be <= 80 characters")
	}
	if patientID == caregiverID {
		return models.Relationship{}, errors.New("relationship requires different patient and caregiver users")
	}
	now := time.Now().UTC()
	relationship := models.Relationship{
		ID:          "rel_" + uuid.NewString(),
		PatientID:   patientID,
		CaregiverID: caregiverID,
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.store.UpsertRelationship(ctx, relationship); err != nil {
		return models.Relationship{}, err
	}
	return relationship, nil
}

func (s Service) RevokeCaregiver(ctx context.Context, patientID, caregiverID string) (models.Relationship, error) {
	patientID = strings.TrimSpace(patientID)
	caregiverID = strings.TrimSpace(caregiverID)
	if patientID == "" || caregiverID == "" {
		return models.Relationship{}, errors.New("patient_id and caregiver_id are required")
	}
	if len(patientID) > 80 || len(caregiverID) > 80 {
		return models.Relationship{}, errors.New("patient_id and caregiver_id must be <= 80 characters")
	}
	if patientID == caregiverID {
		return models.Relationship{}, errors.New("relationship requires different patient and caregiver users")
	}
	now := time.Now().UTC()
	relationship := models.Relationship{
		ID:          "rel_" + uuid.NewString(),
		PatientID:   patientID,
		CaregiverID: caregiverID,
		Status:      "revoked",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.store.UpsertRelationship(ctx, relationship); err != nil {
		return models.Relationship{}, err
	}
	return relationship, nil
}
