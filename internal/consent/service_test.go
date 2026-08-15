package consent

import (
	"context"
	"errors"
	"testing"

	"healthos/backend/internal/models"
)

type fakeStore struct {
	consent models.Consent
	err     error
}

func (f *fakeStore) UpsertConsent(ctx context.Context, consent models.Consent) error {
	if f.err != nil {
		return f.err
	}
	f.consent = consent
	return nil
}

type fakeBroadcaster struct {
	events []any
}

func (f *fakeBroadcaster) Broadcast(payload any) {
	f.events = append(f.events, payload)
}

func TestGrantPersistsConsentAndBroadcastsEvent(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	broadcaster := &fakeBroadcaster{}
	service := New(store, broadcaster)

	consent, err := service.Grant(context.Background(), "usr_patient", "cg_1", []string{models.ScopeReadPatient, models.ScopeReadAlerts, models.ScopeReadPatient})
	if err != nil {
		t.Fatalf("Grant returned error: %v", err)
	}
	if consent.ID == "" || consent.Revoked || len(consent.Scopes) != 2 {
		t.Fatalf("unexpected consent: %#v", consent)
	}
	if store.consent.PatientID != "usr_patient" || store.consent.CaregiverID != "cg_1" {
		t.Fatalf("consent was not persisted: %#v", store.consent)
	}
	if len(broadcaster.events) != 1 {
		t.Fatalf("expected one event, got %d", len(broadcaster.events))
	}
	event, ok := broadcaster.events[0].(map[string]any)
	if !ok || event["type"] != "consent.updated" || event["patientId"] != "usr_patient" || event["caregiverId"] != "cg_1" {
		t.Fatalf("unexpected event payload: %#v", broadcaster.events[0])
	}
}

func TestRevokePersistsRevokedConsentAndBroadcastsEvent(t *testing.T) {
	store := &fakeStore{}
	broadcaster := &fakeBroadcaster{}
	service := New(store, broadcaster)

	consent, err := service.Revoke(context.Background(), " usr_patient ", " cg_1 ")
	if err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
	if consent.ID == "" || !consent.Revoked || len(consent.Scopes) != 0 {
		t.Fatalf("unexpected revoked consent: %#v", consent)
	}
	if store.consent.PatientID != "usr_patient" || store.consent.CaregiverID != "cg_1" || !store.consent.Revoked {
		t.Fatalf("revoked consent was not persisted: %#v", store.consent)
	}
	if len(broadcaster.events) != 1 {
		t.Fatalf("expected one event, got %d", len(broadcaster.events))
	}
}

func TestGrantRejectsInvalidInputAndPersistenceErrors(t *testing.T) {
	t.Parallel()
	service := New(&fakeStore{}, nil)
	cases := []struct {
		name        string
		patientID   string
		caregiverID string
		scopes      []string
	}{
		{name: "missing patient", caregiverID: "cg_1", scopes: []string{models.ScopeReadPatient}},
		{name: "missing caregiver", patientID: "usr_1", scopes: []string{models.ScopeReadPatient}},
		{name: "empty scopes", patientID: "usr_1", caregiverID: "cg_1"},
		{name: "unsupported scope", patientID: "usr_1", caregiverID: "cg_1", scopes: []string{"write:everything"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := service.Grant(context.Background(), tc.patientID, tc.caregiverID, tc.scopes); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}

	failing := New(&fakeStore{err: errors.New("db down")}, nil)
	if _, err := failing.Grant(context.Background(), "usr_1", "cg_1", []string{models.ScopeReadPatient}); err == nil {
		t.Fatal("expected persistence error")
	}

	if _, err := service.Revoke(context.Background(), "usr_1", "usr_1"); err == nil {
		t.Fatal("expected revoke validation error")
	}
	if _, err := failing.Revoke(context.Background(), "usr_1", "cg_1"); err == nil {
		t.Fatal("expected revoke persistence error")
	}
}
