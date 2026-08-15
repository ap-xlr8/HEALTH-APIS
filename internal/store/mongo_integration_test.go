//go:build integration

package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.mongodb.org/mongo-driver/bson"

	"healthos/backend/internal/models"
)

func TestMongoIntegration(t *testing.T) {
	if os.Getenv("CI") == "" && os.Getenv("RUN_TESTCONTAINERS") != "1" {
		t.Skip("skipping testcontainers integration test outside CI; set RUN_TESTCONTAINERS=1 to run locally")
	}
	ctx := context.Background()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "mongo:6.0",
			ExposedPorts: []string{"27017/tcp"},
			WaitingFor:   wait.ForListeningPort("27017/tcp").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("starting mongo container: %v", err)
	}
	t.Cleanup(func() {
		_ = container.Terminate(ctx)
	})

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "27017/tcp")
	if err != nil {
		t.Fatalf("container port: %v", err)
	}
	mongoStore, err := NewMongo(ctx, "mongodb://"+host+":"+port.Port()+"/healthos", "healthos")
	if err != nil {
		t.Fatalf("NewMongo: %v", err)
	}
	t.Cleanup(func() {
		_ = mongoStore.Close(ctx)
	})

	if err := mongoStore.EnsureIndexes(ctx); err != nil {
		t.Fatalf("EnsureIndexes: %v", err)
	}

	user := models.User{
		ID:           "usr_patient",
		Email:        "patient@example.com",
		PasswordHash: "hash",
		Role:         models.RolePatient,
		FirstName:    "Juan",
		LastName:     "Perez",
		CreatedAt:    time.Now().UTC(),
	}
	if err := mongoStore.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if got, err := mongoStore.FindUserByEmail(ctx, user.Email); err != nil || got.ID != user.ID {
		t.Fatalf("FindUserByEmail got=%#v err=%v", got, err)
	}
	if got, err := mongoStore.FindUserByID(ctx, user.ID); err != nil || got.Email != user.Email {
		t.Fatalf("FindUserByID got=%#v err=%v", got, err)
	}

	session := models.Session{
		ID:        "refresh_test",
		UserID:    user.ID,
		Kind:      "refresh",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		CreatedAt: time.Now().UTC(),
	}
	if err := mongoStore.CreateSession(ctx, session); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if got, err := mongoStore.FindSessionByID(ctx, session.ID); err != nil || got.UserID != user.ID {
		t.Fatalf("FindSessionByID got=%#v err=%v", got, err)
	}
	if err := mongoStore.DeleteSessionByID(ctx, session.ID); err != nil {
		t.Fatalf("DeleteSessionByID: %v", err)
	}

	measurement := models.Measurement{
		ID:        "meas_1",
		PatientID: user.ID,
		DeviceID:  "dev_1",
		Type:      "heart_rate",
		Value:     75,
		Unit:      "bpm",
		Timestamp: time.Now().UTC(),
		CreatedAt: time.Now().UTC(),
	}
	if err := mongoStore.InsertMeasurements(ctx, []models.Measurement{measurement}); err != nil {
		t.Fatalf("InsertMeasurements: %v", err)
	}
	alert := models.Alert{
		ID:             "alrt_1",
		PatientID:      user.ID,
		Type:           "tachycardia",
		Severity:       "critical",
		Message:        "test",
		MeasurementRef: measurement.ID,
		CreatedAt:      time.Now().UTC(),
	}
	if err := mongoStore.CreateAlert(ctx, alert); err != nil {
		t.Fatalf("CreateAlert: %v", err)
	}
	if got, err := mongoStore.FindAlertByID(ctx, alert.ID); err != nil || got.PatientID != user.ID {
		t.Fatalf("FindAlertByID got=%#v err=%v", got, err)
	}

	if _, err := mongoStore.db.Collection("relationships").InsertOne(ctx, bson.M{
		"_id": "rel_1", "caregiver_id": "cg_1", "patient_id": user.ID, "status": "active",
	}); err != nil {
		t.Fatalf("insert relationship: %v", err)
	}
	if ok, err := mongoStore.HasActiveRelationship(ctx, "cg_1", user.ID); err != nil || !ok {
		t.Fatalf("HasActiveRelationship ok=%v err=%v", ok, err)
	}
	if _, err := mongoStore.db.Collection("consents").InsertOne(ctx, bson.M{
		"_id": "con_1", "caregiver_id": "cg_1", "patient_id": user.ID, "revoked": false, "scopes": []string{models.ScopeReadPatient},
	}); err != nil {
		t.Fatalf("insert consent: %v", err)
	}
	if ok, err := mongoStore.HasConsentScope(ctx, "cg_1", user.ID, models.ScopeReadPatient); err != nil || !ok {
		t.Fatalf("HasConsentScope ok=%v err=%v", ok, err)
	}
	if err := mongoStore.UpsertConsent(ctx, models.Consent{
		ID:          "con_upsert",
		PatientID:   user.ID,
		CaregiverID: "cg_2",
		Scopes:      []string{models.ScopeReadPatient, models.ScopeReadAlerts},
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertConsent: %v", err)
	}
	if ok, err := mongoStore.HasConsentScope(ctx, "cg_2", user.ID, models.ScopeReadAlerts); err != nil || !ok {
		t.Fatalf("HasConsentScope upserted ok=%v err=%v", ok, err)
	}

	if err := mongoStore.WriteAudit(ctx, models.AuditLog{ID: "aud_1", UserID: user.ID, Action: "integration", Resource: "test", Allowed: true, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("WriteAudit: %v", err)
	}
	if err := mongoStore.CreateClinicalRecord(ctx, models.ClinicalRecord{ID: "clin_1", PatientID: user.ID, Conditions: []string{"hypertension"}, Allergies: []string{"penicillin"}, RecordedBy: "doc_1", RecordedAt: time.Now().UTC(), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CreateClinicalRecord: %v", err)
	}
	if err := mongoStore.CreateMedication(ctx, models.Medication{ID: "med_1", PatientID: user.ID, Name: "Amlodipine", Dosage: "5mg", Schedule: "daily", Active: true, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CreateMedication: %v", err)
	}
	if err := mongoStore.RecordMedicationLog(ctx, models.MedicationLog{ID: "mlog_1", PatientID: user.ID, MedicationID: "med_1", Status: "taken", TakenAt: time.Now().UTC(), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("RecordMedicationLog: %v", err)
	}
	if err := mongoStore.CreateDevice(ctx, models.Device{ID: "dev_2", OwnerID: user.ID, SerialNumber: "SN-1", Type: "wearable", Status: "active", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	if err := mongoStore.CreateDeviceTransferRequest(ctx, models.DeviceTransferRequest{ID: "dtr_1", DeviceID: "dev_2", FromOwnerID: user.ID, ToOwnerID: "usr_next", Status: "pending", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CreateDeviceTransferRequest: %v", err)
	}
	if err := mongoStore.CreateReport(ctx, models.Report{ID: "rep_1", PatientID: user.ID, URL: "s3://reports/rep_1.pdf", Format: "pdf", CreatedBy: "doc_1", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CreateReport: %v", err)
	}
	if err := mongoStore.CreateNotification(ctx, models.Notification{ID: "not_1", UserID: user.ID, Channel: "push", Title: "Vitals", Body: "Review alert", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CreateNotification: %v", err)
	}
	if err := mongoStore.CreateSupportTicket(ctx, models.SupportTicket{ID: "sup_1", UserID: user.ID, Status: "open", Subject: "Help", Body: "Support request", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CreateSupportTicket: %v", err)
	}
}
