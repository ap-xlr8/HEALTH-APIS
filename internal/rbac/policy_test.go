package rbac

import (
	"testing"

	"healthos/backend/internal/models"
)

func TestPolicyAllowsExplicitRoles(t *testing.T) {
	t.Parallel()
	policy := NewPolicy([]string{models.RolePatient, models.RoleCaregiver})
	if !policy.Allows(models.RolePatient) || !policy.Allows(models.RoleCaregiver) {
		t.Fatal("expected patient and caregiver to be allowed")
	}
	if policy.Allows(models.RoleAdmin) {
		t.Fatal("expected admin to be denied")
	}
}

func TestPolicyWithoutRolesAllowsAnyRole(t *testing.T) {
	t.Parallel()
	policy := NewPolicy(nil)
	if !policy.Allows(models.RolePatient) || !policy.Allows(models.RoleAdmin) {
		t.Fatal("expected unrestricted policy to allow any role")
	}
}
