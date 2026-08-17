package relationships

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"

	"healthos/backend/internal/models"
)

type Store interface {
	UpsertRelationship(ctx context.Context, relationship models.Relationship) error
	FindRelationshipByID(ctx context.Context, id string) (models.Relationship, error)
	ListRelationshipsForUser(ctx context.Context, userID, role string) ([]models.Relationship, error)
	FindUserByEmail(ctx context.Context, email string) (models.User, error)
	FindUserByID(ctx context.Context, id string) (models.User, error)
	CreateLinkingCode(ctx context.Context, code models.LinkingCode) error
	FindActiveLinkingCode(ctx context.Context, code string) (models.LinkingCode, error)
	FindActiveLinkingCodeForUser(ctx context.Context, userID string) (models.LinkingCode, error)
	ClaimLinkingCode(ctx context.Context, code, claimantID string) (models.LinkingCode, error)
	UpsertConsent(ctx context.Context, consent models.Consent) error
}

type Service struct {
	store Store
}

func New(store Store) Service {
	return Service{store: store}
}

const codeCharset = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

func generateRandomPIN(length int) (string, error) {
	bytes := make([]byte, length)
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(codeCharset))))
		if err != nil {
			return "", err
		}
		bytes[i] = codeCharset[num.Int64()]
	}
	return string(bytes), nil
}

func (s Service) GenerateLinkingCode(ctx context.Context, creatorID, creatorRole, creatorName string) (models.LinkingCode, error) {
	creatorID = strings.TrimSpace(creatorID)
	if creatorID == "" {
		return models.LinkingCode{}, errors.New("creator_id is required")
	}

	pin, err := generateRandomPIN(6)
	if err != nil {
		pin = strings.ToUpper(uuid.NewString()[:6])
	}

	now := time.Now().UTC()
	linkingCode := models.LinkingCode{
		ID:          "lk_" + uuid.NewString(),
		Code:        pin,
		CreatorID:   creatorID,
		CreatorRole: creatorRole,
		CreatorName: creatorName,
		Status:      "pending",
		ExpiresAt:   now.Add(30 * time.Minute),
		CreatedAt:   now,
	}

	if err := s.store.CreateLinkingCode(ctx, linkingCode); err != nil {
		return models.LinkingCode{}, err
	}
	return linkingCode, nil
}

func (s Service) GetActiveLinkingCode(ctx context.Context, userID string) (models.LinkingCode, error) {
	return s.store.FindActiveLinkingCodeForUser(ctx, userID)
}

func (s Service) ClaimLinkingCode(ctx context.Context, codeStr, claimantID, claimantRole string, scopes []string) (models.Relationship, error) {
	codeStr = strings.ToUpper(strings.TrimSpace(codeStr))
	claimantID = strings.TrimSpace(claimantID)
	if codeStr == "" || claimantID == "" {
		return models.Relationship{}, errors.New("código y usuario son requeridos")
	}

	lk, err := s.store.FindActiveLinkingCode(ctx, codeStr)
	if err != nil {
		return models.Relationship{}, errors.New("el código de vinculación es inválido o ha expirado")
	}

	if lk.CreatorID == claimantID {
		return models.Relationship{}, errors.New("no puedes canjear un código generado por tu propia cuenta")
	}

	patientID := lk.CreatorID
	caregiverID := claimantID

	if lk.CreatorRole == models.RoleCaregiver || claimantRole == models.RolePatient {
		patientID = claimantID
		caregiverID = lk.CreatorID
	}

	// Claim code
	if _, err := s.store.ClaimLinkingCode(ctx, codeStr, claimantID); err != nil {
		return models.Relationship{}, errors.New("no se pudo validar el código de vinculación")
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

	if len(scopes) == 0 {
		scopes = []string{
			models.ScopeReadMeasurements,
			models.ScopeWriteMeasurements,
			models.ScopeReadPatient,
			models.ScopeWritePatient,
			models.ScopeReadAlerts,
			models.ScopeWriteClinical,
			models.ScopeReadClinical,
			models.ScopeReadReports,
		}
	}

	consent := models.Consent{
		ID:          "cs_" + uuid.NewString(),
		PatientID:   patientID,
		CaregiverID: caregiverID,
		Scopes:      scopes,
		Revoked:     false,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	_ = s.store.UpsertConsent(ctx, consent)

	return relationship, nil
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

	// Always ensure default active consent exists for this pair
	consent := models.Consent{
		ID:          "cs_" + uuid.NewString(),
		PatientID:   patientID,
		CaregiverID: caregiverID,
		Scopes: []string{
			models.ScopeReadMeasurements,
			models.ScopeWriteMeasurements,
			models.ScopeReadPatient,
			models.ScopeWritePatient,
			models.ScopeReadAlerts,
			models.ScopeWriteClinical,
			models.ScopeReadClinical,
			models.ScopeReadReports,
		},
		Revoked:   false,
		CreatedAt: now,
		UpdatedAt: now,
	}
	_ = s.store.UpsertConsent(ctx, consent)

	return relationship, nil
}

func (s Service) RevokeCaregiver(ctx context.Context, callerID, targetID string) (models.Relationship, error) {
	callerID = strings.TrimSpace(callerID)
	targetID = strings.TrimSpace(targetID)
	if callerID == "" || targetID == "" {
		return models.Relationship{}, errors.New("identificadores requeridos para revocación")
	}
	if callerID == targetID && !strings.HasPrefix(targetID, "rel_") {
		return models.Relationship{}, errors.New("relationship requires different patient and caregiver users")
	}
	if len(callerID) > 80 || len(targetID) > 80 {
		return models.Relationship{}, errors.New("patient_id and caregiver_id must be <= 80 characters")
	}

	patientID := callerID
	caregiverID := targetID

	// 1. If targetID is a relationship document ID (rel_...)
	if strings.HasPrefix(targetID, "rel_") {
		if rel, err := s.store.FindRelationshipByID(ctx, targetID); err == nil && rel.ID != "" {
			patientID = rel.PatientID
			caregiverID = rel.CaregiverID
		}
	} else if strings.Contains(targetID, "@") {
		// 2. If targetID is an email
		if u, err := s.store.FindUserByEmail(ctx, strings.ToLower(targetID)); err == nil && u.ID != "" {
			targetID = u.ID
			caregiverID = u.ID
		}
	}

	// 3. Determine if caller is patient or caregiver
	if caller, err := s.store.FindUserByID(ctx, callerID); err == nil && caller.ID != "" {
		if caller.Role == models.RoleCaregiver {
			caregiverID = caller.ID
			if !strings.HasPrefix(targetID, "rel_") {
				patientID = targetID
			}
		} else if caller.Role == models.RolePatient {
			patientID = caller.ID
			if !strings.HasPrefix(targetID, "rel_") {
				caregiverID = targetID
			}
		}
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

	// Revoke all consent scopes completely
	consent := models.Consent{
		ID:          "con_" + uuid.NewString(),
		PatientID:   patientID,
		CaregiverID: caregiverID,
		Scopes:      []string{},
		Revoked:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	_ = s.store.UpsertConsent(ctx, consent)

	return relationship, nil
}
