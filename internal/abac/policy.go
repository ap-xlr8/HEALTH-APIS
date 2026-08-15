package abac

import (
	"context"

	"healthos/backend/internal/models"
)

type Resolver interface {
	HasActiveRelationship(ctx context.Context, caregiverID, patientID string) (bool, error)
	HasConsentScope(ctx context.Context, caregiverID, patientID, scope string) (bool, error)
}

func Decide(ctx context.Context, resolver Resolver, user models.User, patientID, scope string) (bool, string) {
	if user.Role == models.RoleAdmin {
		return true, "admin access"
	}
	if patientID == "" {
		return user.Role == models.RolePatient || user.Role == models.RoleCaregiver, "role access"
	}
	if user.Role == models.RolePatient {
		if user.ID != patientID {
			return false, "patient can only access own resources"
		}
		return true, "patient owns resource"
	}
	if user.Role == models.RoleCaregiver {
		hasRelationship, err := resolver.HasActiveRelationship(ctx, user.ID, patientID)
		if err != nil {
			return false, "relationship lookup failed"
		}
		if !hasRelationship {
			return false, "active caregiver-patient relationship required"
		}
		hasConsent, err := resolver.HasConsentScope(ctx, user.ID, patientID, scope)
		if err != nil {
			return false, "consent lookup failed"
		}
		if !hasConsent {
			return false, "patient consent scope required"
		}
		return true, "relationship and consent approved"
	}
	return false, "role is not allowed"
}
