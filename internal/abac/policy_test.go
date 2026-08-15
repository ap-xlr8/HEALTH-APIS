package abac

import (
	"context"
	"errors"
	"testing"

	"healthos/backend/internal/models"
)

type fakeResolver struct {
	relationship bool
	consent      bool
	relErr       error
	consentErr   error
}

func (f fakeResolver) HasActiveRelationship(ctx context.Context, caregiverID, patientID string) (bool, error) {
	return f.relationship, f.relErr
}

func (f fakeResolver) HasConsentScope(ctx context.Context, caregiverID, patientID, scope string) (bool, error) {
	return f.consent, f.consentErr
}

func TestDecidePatientOwnershipAndAdmin(t *testing.T) {
	t.Parallel()
	adminAllowed, adminReason := Decide(context.Background(), fakeResolver{}, models.User{ID: "admin_1", Role: models.RoleAdmin}, "usr_1", models.ScopeReadPatient)
	if !adminAllowed || adminReason != "admin access" {
		t.Fatalf("expected admin access, got allowed=%v reason=%q", adminAllowed, adminReason)
	}

	patientAllowed, patientReason := Decide(context.Background(), fakeResolver{}, models.User{ID: "usr_1", Role: models.RolePatient}, "usr_1", models.ScopeReadPatient)
	if !patientAllowed || patientReason != "patient owns resource" {
		t.Fatalf("expected patient ownership, got allowed=%v reason=%q", patientAllowed, patientReason)
	}

	otherAllowed, otherReason := Decide(context.Background(), fakeResolver{}, models.User{ID: "usr_1", Role: models.RolePatient}, "usr_2", models.ScopeReadPatient)
	if otherAllowed || otherReason != "patient can only access own resources" {
		t.Fatalf("expected patient denial, got allowed=%v reason=%q", otherAllowed, otherReason)
	}
}

func TestDecideCaregiverRelationshipAndConsent(t *testing.T) {
	t.Parallel()
	user := models.User{ID: "cg_1", Role: models.RoleCaregiver}
	allowed, reason := Decide(context.Background(), fakeResolver{relationship: true, consent: true}, user, "usr_1", models.ScopeReadPatient)
	if !allowed || reason != "relationship and consent approved" {
		t.Fatalf("expected caregiver approval, got allowed=%v reason=%q", allowed, reason)
	}

	allowed, reason = Decide(context.Background(), fakeResolver{}, user, "usr_1", models.ScopeReadPatient)
	if allowed || reason != "active caregiver-patient relationship required" {
		t.Fatalf("expected relationship denial, got allowed=%v reason=%q", allowed, reason)
	}

	allowed, reason = Decide(context.Background(), fakeResolver{relationship: true}, user, "usr_1", models.ScopeReadPatient)
	if allowed || reason != "patient consent scope required" {
		t.Fatalf("expected consent denial, got allowed=%v reason=%q", allowed, reason)
	}
}

func TestDecideLookupErrorsAndNoPatientResource(t *testing.T) {
	t.Parallel()
	user := models.User{ID: "cg_1", Role: models.RoleCaregiver}
	allowed, reason := Decide(context.Background(), fakeResolver{relErr: errors.New("db")}, user, "usr_1", models.ScopeReadPatient)
	if allowed || reason != "relationship lookup failed" {
		t.Fatalf("expected relationship lookup error, got allowed=%v reason=%q", allowed, reason)
	}

	allowed, reason = Decide(context.Background(), fakeResolver{relationship: true, consentErr: errors.New("db")}, user, "usr_1", models.ScopeReadPatient)
	if allowed || reason != "consent lookup failed" {
		t.Fatalf("expected consent lookup error, got allowed=%v reason=%q", allowed, reason)
	}

	allowed, reason = Decide(context.Background(), fakeResolver{}, user, "", models.ScopeReadPatient)
	if !allowed || reason != "role access" {
		t.Fatalf("expected role access, got allowed=%v reason=%q", allowed, reason)
	}
}
