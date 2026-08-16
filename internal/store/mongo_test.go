package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"healthos/backend/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/event"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/integration/mtest"
)

func TestNormalizeFindErr(t *testing.T) {
	t.Parallel()
	if got := normalizeFindErr(mongo.ErrNoDocuments); got != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", got)
	}
	err := errors.New("boom")
	if got := normalizeFindErr(err); got != err {
		t.Fatalf("expected original error, got %v", got)
	}
}

func TestConnectWithRetry(t *testing.T) {
	t.Parallel()

	t.Run("retries then succeeds with growing backoff", func(t *testing.T) {
		t.Parallel()
		var attempts int
		err := connectWithRetry(context.Background(), 2*time.Second, time.Millisecond, 10*time.Millisecond, func(ctx context.Context) error {
			attempts++
			if attempts < 3 {
				return errors.New("boom")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if attempts != 3 {
			t.Fatalf("expected 3 attempts, got %d", attempts)
		}
	})

	t.Run("caps backoff at max", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
		defer cancel()
		err := connectWithRetry(ctx, time.Hour, time.Millisecond, time.Millisecond, func(ctx context.Context) error {
			return errors.New("boom")
		})
		if err == nil {
			t.Fatal("expected error after deadline")
		}
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			t.Fatalf("expected deadline error, got %v", err)
		}
	})

	t.Run("succeeds immediately", func(t *testing.T) {
		t.Parallel()
		var attempts int
		err := connectWithRetry(context.Background(), time.Second, time.Millisecond, time.Millisecond, func(ctx context.Context) error {
			attempts++
			return nil
		})
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if attempts != 1 {
			t.Fatalf("expected 1 attempt, got %d", attempts)
		}
	})
}

func TestInsertMeasurementsEmpty(t *testing.T) {
	t.Parallel()
	var m Mongo
	if err := m.InsertMeasurements(nil, nil); err != nil {
		t.Fatalf("expected empty insert to be noop, got %v", err)
	}
}

func TestNewMongoRejectsInvalidURI(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := NewMongo(ctx, "://bad-uri", "healthos"); err == nil {
		t.Fatal("expected invalid mongo uri error")
	}
}

func TestForbiddenAuditMutation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		commandName string
		command     bson.D
		want        bool
	}{
		{name: "update audit logs", commandName: "update", command: bson.D{{Key: "update", Value: "audit_logs"}}, want: true},
		{name: "delete audit logs", commandName: "delete", command: bson.D{{Key: "delete", Value: "audit_logs"}}, want: true},
		{name: "find and modify audit logs", commandName: "findAndModify", command: bson.D{{Key: "findAndModify", Value: "audit_logs"}}, want: true},
		{name: "insert audit logs allowed", commandName: "insert", command: bson.D{{Key: "insert", Value: "audit_logs"}}, want: false},
		{name: "update users ignored", commandName: "update", command: bson.D{{Key: "update", Value: "users"}}, want: false},
		{name: "malformed command ignored", commandName: "update", command: bson.D{{Key: "update", Value: 123}}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := bson.Marshal(tc.command)
			if err != nil {
				t.Fatalf("Marshal returned error: %v", err)
			}
			got := forbiddenAuditMutation(&event.CommandStartedEvent{
				CommandName: tc.commandName,
				Command:     raw,
			})
			if got != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
	if forbiddenAuditMutation(nil) {
		t.Fatal("nil event should not be a forbidden mutation")
	}
}

func TestZeroMongoPanicsForDBOperations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	zero := &Mongo{}
	cases := []struct {
		name string
		fn   func()
	}{
		{"Close", func() { _ = zero.Close(ctx) }},
		{"EnsureIndexes", func() { _ = zero.EnsureIndexes(ctx) }},
		{"CreateUser", func() { _ = zero.CreateUser(ctx, models.User{}) }},
		{"FindUserByEmail", func() { _, _ = zero.FindUserByEmail(ctx, "x@example.com") }},
		{"FindUserByID", func() { _, _ = zero.FindUserByID(ctx, "usr_1") }},
		{"CreateSession", func() { _ = zero.CreateSession(ctx, models.Session{}) }},
		{"FindSessionByID", func() { _, _ = zero.FindSessionByID(ctx, "refresh_1") }},
		{"DeleteSessionByID", func() { _ = zero.DeleteSessionByID(ctx, "refresh_1") }},
		{"InsertMeasurements", func() { _ = zero.InsertMeasurements(ctx, []models.Measurement{{ID: "meas_1"}}) }},
		{"ListMeasurements", func() { _, _ = zero.ListMeasurements(ctx, models.MeasurementFilter{PatientID: "usr_1"}) }},
		{"CreateAlert", func() { _ = zero.CreateAlert(ctx, models.Alert{}) }},
		{"FindAlertByID", func() { _, _ = zero.FindAlertByID(ctx, "alrt_1") }},
		{"AcknowledgeAlert", func() { _, _ = zero.AcknowledgeAlert(ctx, "alrt_1") }},
		{"HasActiveRelationship", func() { _, _ = zero.HasActiveRelationship(ctx, "cg_1", "usr_1") }},
		{"UpsertRelationship", func() { _ = zero.UpsertRelationship(ctx, models.Relationship{}) }},
		{"ListRelationshipsForUser", func() { _, _ = zero.ListRelationshipsForUser(ctx, "usr_1", models.RolePatient) }},
		{"HasConsentScope", func() { _, _ = zero.HasConsentScope(ctx, "cg_1", "usr_1", models.ScopeReadPatient) }},
		{"UpsertConsent", func() { _ = zero.UpsertConsent(ctx, models.Consent{}) }},
		{"WriteAudit", func() { _ = zero.WriteAudit(ctx, models.AuditLog{}) }},
		{"CreateClinicalRecord", func() { _ = zero.CreateClinicalRecord(ctx, models.ClinicalRecord{}) }},
		{"CreateMedication", func() { _ = zero.CreateMedication(ctx, models.Medication{}) }},
		{"RecordMedicationLog", func() { _ = zero.RecordMedicationLog(ctx, models.MedicationLog{}) }},
		{"CreateDevice", func() { _ = zero.CreateDevice(ctx, models.Device{}) }},
		{"CreateDeviceTransferRequest", func() { _ = zero.CreateDeviceTransferRequest(ctx, models.DeviceTransferRequest{}) }},
		{"FindDeviceTransferRequestByID", func() { _, _ = zero.FindDeviceTransferRequestByID(ctx, "dtr_1") }},
		{"UpdateDeviceTransferRequestStatus", func() { _, _ = zero.UpdateDeviceTransferRequestStatus(ctx, "dtr_1", "approved", time.Now()) }},
		{"UpdateDeviceOwner", func() { _ = zero.UpdateDeviceOwner(ctx, "dev_1", "usr_2", time.Now()) }},
		{"CreateReport", func() { _ = zero.CreateReport(ctx, models.Report{}) }},
		{"CreateNotification", func() { _ = zero.CreateNotification(ctx, models.Notification{}) }},
		{"CreateSupportTicket", func() { _ = zero.CreateSupportTicket(ctx, models.SupportTicket{}) }},
		{"UpsertSubscriptionEvent", func() { _ = zero.UpsertSubscriptionEvent(ctx, models.Subscription{}) }},
		{"CreateBreakGlassRequest", func() { _ = zero.CreateBreakGlassRequest(ctx, models.BreakGlassRequest{}) }},
		{"FindBreakGlassRequestByID", func() { _, _ = zero.FindBreakGlassRequestByID(ctx, "bgr_1") }},
		{"ApproveBreakGlassRequest", func() { _, _ = zero.ApproveBreakGlassRequest(ctx, "bgr_1", "admin_2", time.Now()) }},
		{"createCollectionIfMissing", func() { _ = zero.createCollectionIfMissing(ctx, "users") }},
		{"createTimeSeriesIfMissing", func() { _ = zero.createTimeSeriesIfMissing(ctx) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mustPanic(t, tc.fn)
		})
	}
}

func TestMongoMethodsWithMockDeployment(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock).CreateClient(true).CreateCollection(false))
	ctx := context.Background()
	now := time.Now().UTC()

	mt.Run("writes", func(mt *mtest.T) {
		mongoStore := &Mongo{client: mt.Client, db: mt.Client.Database("healthos")}
		mt.AddMockResponses(
			mtest.CreateSuccessResponse(),
			mtest.CreateSuccessResponse(),
			mtest.CreateSuccessResponse(),
			mtest.CreateCursorResponse(0, "healthos.health_measurements", mtest.FirstBatch, bson.D{{Key: "_id", Value: "meas_1"}, {Key: "patient_id", Value: "usr_1"}, {Key: "device_id", Value: "dev_1"}, {Key: "type", Value: "heart_rate"}, {Key: "value", Value: 75.0}, {Key: "unit", Value: "bpm"}, {Key: "timestamp", Value: now}, {Key: "created_at", Value: now}}),
			mtest.CreateSuccessResponse(),
			mtest.CreateSuccessResponse(
				bson.E{Key: "lastErrorObject", Value: bson.D{{Key: "n", Value: 1}}},
				bson.E{Key: "value", Value: bson.D{{Key: "_id", Value: "alrt_1"}, {Key: "patient_id", Value: "usr_1"}, {Key: "type", Value: "tachycardia"}, {Key: "severity", Value: "critical"}, {Key: "message", Value: "test"}, {Key: "measurement_ref", Value: "meas_1"}, {Key: "acknowledged", Value: true}, {Key: "created_at", Value: now}}},
			),
			mtest.CreateSuccessResponse(),
			mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}, bson.E{Key: "nModified", Value: 1}, bson.E{Key: "upserted", Value: bson.A{}}),
			mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}, bson.E{Key: "nModified", Value: 1}, bson.E{Key: "upserted", Value: bson.A{}}),
			mtest.CreateSuccessResponse(),
			mtest.CreateSuccessResponse(),
			mtest.CreateSuccessResponse(),
			mtest.CreateSuccessResponse(),
			mtest.CreateSuccessResponse(),
			mtest.CreateSuccessResponse(),
			mtest.CreateCursorResponse(0, "healthos.device_transfer_requests", mtest.FirstBatch, bson.D{{Key: "_id", Value: "dtr_1"}, {Key: "device_id", Value: "dev_1"}, {Key: "from_owner_id", Value: "usr_1"}, {Key: "to_owner_id", Value: "usr_2"}, {Key: "status", Value: "pending"}, {Key: "created_at", Value: now}, {Key: "updated_at", Value: now}}),
			mtest.CreateSuccessResponse(
				bson.E{Key: "lastErrorObject", Value: bson.D{{Key: "n", Value: 1}}},
				bson.E{Key: "value", Value: bson.D{{Key: "_id", Value: "dtr_1"}, {Key: "device_id", Value: "dev_1"}, {Key: "from_owner_id", Value: "usr_1"}, {Key: "to_owner_id", Value: "usr_2"}, {Key: "status", Value: "approved"}, {Key: "created_at", Value: now}, {Key: "updated_at", Value: now}}},
			),
			mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}, bson.E{Key: "nModified", Value: 1}),
			mtest.CreateSuccessResponse(),
			mtest.CreateSuccessResponse(),
			mtest.CreateSuccessResponse(),
			mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}, bson.E{Key: "nModified", Value: 0}, bson.E{Key: "upserted", Value: bson.A{}}),
		)
		if err := mongoStore.CreateUser(ctx, models.User{ID: "usr_1", Email: "u@example.com", CreatedAt: now}); err != nil {
			t.Fatalf("CreateUser returned error: %v", err)
		}
		if err := mongoStore.CreateSession(ctx, models.Session{ID: "refresh_1", UserID: "usr_1", ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatalf("CreateSession returned error: %v", err)
		}
		if err := mongoStore.InsertMeasurements(ctx, []models.Measurement{{ID: "meas_1", PatientID: "usr_1", Timestamp: now}}); err != nil {
			t.Fatalf("InsertMeasurements returned error: %v", err)
		}
		if measurements, err := mongoStore.ListMeasurements(ctx, models.MeasurementFilter{PatientID: "usr_1", Type: "heart_rate", From: now.Add(-time.Hour), To: now, Limit: 10}); err != nil || len(measurements) != 1 || measurements[0].ID != "meas_1" {
			t.Fatalf("ListMeasurements measurements=%#v err=%v", measurements, err)
		}
		if err := mongoStore.CreateAlert(ctx, models.Alert{ID: "alrt_1", PatientID: "usr_1", CreatedAt: now}); err != nil {
			t.Fatalf("CreateAlert returned error: %v", err)
		}
		if alert, err := mongoStore.AcknowledgeAlert(ctx, "alrt_1"); err != nil || !alert.Acknowledged {
			t.Fatalf("AcknowledgeAlert alert=%#v err=%v", alert, err)
		}
		if err := mongoStore.CreateBreakGlassRequest(ctx, models.BreakGlassRequest{ID: "bgr_1", RequesterID: "admin_1", Status: "pending", CreatedAt: now}); err != nil {
			t.Fatalf("CreateBreakGlassRequest returned error: %v", err)
		}
		if err := mongoStore.UpsertRelationship(ctx, models.Relationship{ID: "rel_1", PatientID: "usr_1", CaregiverID: "cg_1", Status: "active", CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatalf("UpsertRelationship returned error: %v", err)
		}
		if err := mongoStore.UpsertConsent(ctx, models.Consent{ID: "con_1", PatientID: "usr_1", CaregiverID: "cg_1", Scopes: []string{models.ScopeReadPatient}, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatalf("UpsertConsent returned error: %v", err)
		}
		if err := mongoStore.WriteAudit(ctx, models.AuditLog{ID: "aud_1", UserID: "usr_1", CreatedAt: now}); err != nil {
			t.Fatalf("WriteAudit returned error: %v", err)
		}
		if err := mongoStore.CreateClinicalRecord(ctx, models.ClinicalRecord{ID: "clin_1", PatientID: "usr_1", RecordedBy: "doc_1", CreatedAt: now}); err != nil {
			t.Fatalf("CreateClinicalRecord returned error: %v", err)
		}
		if err := mongoStore.CreateMedication(ctx, models.Medication{ID: "med_1", PatientID: "usr_1", Name: "Amlodipine", Active: true, CreatedAt: now}); err != nil {
			t.Fatalf("CreateMedication returned error: %v", err)
		}
		if err := mongoStore.RecordMedicationLog(ctx, models.MedicationLog{ID: "mlog_1", PatientID: "usr_1", MedicationID: "med_1", Status: "taken", TakenAt: now}); err != nil {
			t.Fatalf("RecordMedicationLog returned error: %v", err)
		}
		if err := mongoStore.CreateDevice(ctx, models.Device{ID: "dev_1", OwnerID: "usr_1", Type: "wearable", Status: "active", CreatedAt: now}); err != nil {
			t.Fatalf("CreateDevice returned error: %v", err)
		}
		if err := mongoStore.CreateDeviceTransferRequest(ctx, models.DeviceTransferRequest{ID: "dtr_1", DeviceID: "dev_1", FromOwnerID: "usr_1", ToOwnerID: "usr_2", Status: "pending", CreatedAt: now}); err != nil {
			t.Fatalf("CreateDeviceTransferRequest returned error: %v", err)
		}
		if request, err := mongoStore.FindDeviceTransferRequestByID(ctx, "dtr_1"); err != nil || request.ID != "dtr_1" {
			t.Fatalf("FindDeviceTransferRequestByID request=%#v err=%v", request, err)
		}
		if request, err := mongoStore.UpdateDeviceTransferRequestStatus(ctx, "dtr_1", "approved", now); err != nil || request.Status != "approved" {
			t.Fatalf("UpdateDeviceTransferRequestStatus request=%#v err=%v", request, err)
		}
		if err := mongoStore.UpdateDeviceOwner(ctx, "dev_1", "usr_2", now); err != nil {
			t.Fatalf("UpdateDeviceOwner returned error: %v", err)
		}
		if err := mongoStore.CreateReport(ctx, models.Report{ID: "rep_1", PatientID: "usr_1", URL: "s3://reports/rep_1.pdf", Format: "pdf", CreatedBy: "doc_1", CreatedAt: now}); err != nil {
			t.Fatalf("CreateReport returned error: %v", err)
		}
		if err := mongoStore.CreateNotification(ctx, models.Notification{ID: "not_1", UserID: "usr_1", Channel: "push", Title: "Alert", Body: "Check vitals", CreatedAt: now}); err != nil {
			t.Fatalf("CreateNotification returned error: %v", err)
		}
		if err := mongoStore.CreateSupportTicket(ctx, models.SupportTicket{ID: "sup_1", UserID: "usr_1", Status: "open", Subject: "Help", Body: "Need support", CreatedAt: now}); err != nil {
			t.Fatalf("CreateSupportTicket returned error: %v", err)
		}
		if err := mongoStore.UpsertSubscriptionEvent(ctx, models.Subscription{ID: "subevt_1", StripeEventID: "evt_1"}); err != nil {
			t.Fatalf("UpsertSubscriptionEvent returned error: %v", err)
		}
	})

	mt.Run("reads", func(mt *mtest.T) {
		mongoStore := &Mongo{client: mt.Client, db: mt.Client.Database("healthos")}
		userDoc := bson.D{{Key: "_id", Value: "usr_1"}, {Key: "email", Value: "u@example.com"}, {Key: "role", Value: models.RolePatient}, {Key: "first_name", Value: "Juan"}, {Key: "last_name", Value: "Perez"}, {Key: "created_at", Value: now}}
		sessionDoc := bson.D{{Key: "_id", Value: "refresh_1"}, {Key: "user_id", Value: "usr_1"}, {Key: "kind", Value: "refresh"}, {Key: "expires_at", Value: now.Add(time.Hour)}, {Key: "created_at", Value: now}}
		alertDoc := bson.D{{Key: "_id", Value: "alrt_1"}, {Key: "patient_id", Value: "usr_1"}, {Key: "type", Value: "tachycardia"}, {Key: "severity", Value: "critical"}, {Key: "message", Value: "test"}, {Key: "measurement_ref", Value: "meas_1"}, {Key: "acknowledged", Value: false}, {Key: "created_at", Value: now}}
		breakGlassDoc := bson.D{{Key: "_id", Value: "bgr_1"}, {Key: "requester_id", Value: "admin_1"}, {Key: "approver_id", Value: "admin_2"}, {Key: "reason", Value: "incident"}, {Key: "status", Value: "approved"}, {Key: "expires_at", Value: now.Add(time.Hour)}, {Key: "created_at", Value: now}, {Key: "approved_at", Value: now}}
		relationshipDoc := bson.D{{Key: "_id", Value: "rel_1"}, {Key: "caregiver_id", Value: "cg_1"}, {Key: "patient_id", Value: "usr_1"}, {Key: "status", Value: "active"}, {Key: "created_at", Value: now}, {Key: "updated_at", Value: now}}
		clinicalDoc := bson.D{{Key: "_id", Value: "clin_1"}, {Key: "patient_id", Value: "usr_1"}, {Key: "conditions", Value: bson.A{"hypertension"}}, {Key: "allergies", Value: bson.A{"penicillin"}}, {Key: "recorded_by", Value: "doc_1"}, {Key: "recorded_at", Value: now}, {Key: "created_at", Value: now}}
		medicationDoc := bson.D{{Key: "_id", Value: "med_1"}, {Key: "patient_id", Value: "usr_1"}, {Key: "name", Value: "Amlodipine"}, {Key: "dosage", Value: "5mg"}, {Key: "schedule", Value: "daily"}, {Key: "active", Value: true}, {Key: "created_at", Value: now}, {Key: "updated_at", Value: now}}
		deviceDoc := bson.D{{Key: "_id", Value: "dev_1"}, {Key: "owner_id", Value: "usr_1"}, {Key: "serial_number", Value: "SN-1"}, {Key: "type", Value: "wearable"}, {Key: "status", Value: "active"}, {Key: "created_at", Value: now}, {Key: "updated_at", Value: now}}
		reportDoc := bson.D{{Key: "_id", Value: "rep_1"}, {Key: "patient_id", Value: "usr_1"}, {Key: "url", Value: "s3://reports/rep_1.pdf"}, {Key: "format", Value: "pdf"}, {Key: "created_by", Value: "doc_1"}, {Key: "created_at", Value: now}}
		notificationDoc := bson.D{{Key: "_id", Value: "not_1"}, {Key: "user_id", Value: "usr_1"}, {Key: "channel", Value: "push"}, {Key: "title", Value: "Alert"}, {Key: "body", Value: "Check vitals"}, {Key: "created_at", Value: now}}
		ticketDoc := bson.D{{Key: "_id", Value: "sup_1"}, {Key: "user_id", Value: "usr_1"}, {Key: "status", Value: "open"}, {Key: "subject", Value: "Help"}, {Key: "body", Value: "Need support"}, {Key: "created_at", Value: now}, {Key: "updated_at", Value: now}}
		mt.AddMockResponses(
			mtest.CreateCursorResponse(0, "healthos.users", mtest.FirstBatch, userDoc),
			mtest.CreateCursorResponse(0, "healthos.users", mtest.FirstBatch, userDoc),
			mtest.CreateCursorResponse(0, "healthos.sessions", mtest.FirstBatch, sessionDoc),
			mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}),
			mtest.CreateCursorResponse(0, "healthos.health_alerts", mtest.FirstBatch, alertDoc),
			mtest.CreateCursorResponse(0, "healthos.relationships", mtest.FirstBatch, bson.D{{Key: "n", Value: int32(1)}}),
			mtest.CreateCursorResponse(0, "healthos.consents", mtest.FirstBatch, bson.D{{Key: "n", Value: int32(1)}}),
			mtest.CreateSuccessResponse(),
			mtest.CreateCursorResponse(0, "healthos.break_glass_requests", mtest.FirstBatch, breakGlassDoc),
			mtest.CreateSuccessResponse(bson.E{Key: "value", Value: breakGlassDoc}),
			mtest.CreateCursorResponse(0, "healthos.relationships", mtest.FirstBatch, relationshipDoc),
			mtest.CreateCursorResponse(0, "healthos.clinical_records", mtest.FirstBatch, clinicalDoc),
			mtest.CreateCursorResponse(0, "healthos.medications", mtest.FirstBatch, medicationDoc),
			mtest.CreateCursorResponse(0, "healthos.devices", mtest.FirstBatch, deviceDoc),
			mtest.CreateCursorResponse(0, "healthos.reports", mtest.FirstBatch, reportDoc),
			mtest.CreateCursorResponse(0, "healthos.notifications", mtest.FirstBatch, notificationDoc),
			mtest.CreateCursorResponse(0, "healthos.support_tickets", mtest.FirstBatch, ticketDoc),
		)
		if user, err := mongoStore.FindUserByEmail(ctx, "u@example.com"); err != nil || user.ID != "usr_1" {
			t.Fatalf("FindUserByEmail user=%#v err=%v", user, err)
		}
		if user, err := mongoStore.FindUserByID(ctx, "usr_1"); err != nil || user.Email != "u@example.com" {
			t.Fatalf("FindUserByID user=%#v err=%v", user, err)
		}
		if session, err := mongoStore.FindSessionByID(ctx, "refresh_1"); err != nil || session.UserID != "usr_1" {
			t.Fatalf("FindSessionByID session=%#v err=%v", session, err)
		}
		if err := mongoStore.DeleteSessionByID(ctx, "refresh_1"); err != nil {
			t.Fatalf("DeleteSessionByID returned error: %v", err)
		}
		if alert, err := mongoStore.FindAlertByID(ctx, "alrt_1"); err != nil || alert.PatientID != "usr_1" {
			t.Fatalf("FindAlertByID alert=%#v err=%v", alert, err)
		}
		if ok, err := mongoStore.HasActiveRelationship(ctx, "cg_1", "usr_1"); err != nil || !ok {
			t.Fatalf("HasActiveRelationship ok=%v err=%v", ok, err)
		}
		if ok, err := mongoStore.HasConsentScope(ctx, "cg_1", "usr_1", models.ScopeReadPatient); err != nil || !ok {
			t.Fatalf("HasConsentScope ok=%v err=%v", ok, err)
		}
		if err := mongoStore.WriteAudit(ctx, models.AuditLog{ID: "aud_1", UserID: "usr_1", CreatedAt: now}); err != nil {
			t.Fatalf("WriteAudit returned error: %v", err)
		}
		if request, err := mongoStore.FindBreakGlassRequestByID(ctx, "bgr_1"); err != nil || request.RequesterID != "admin_1" {
			t.Fatalf("FindBreakGlassRequestByID request=%#v err=%v", request, err)
		}
		if request, err := mongoStore.ApproveBreakGlassRequest(ctx, "bgr_1", "admin_2", now); err != nil || request.Status != "approved" {
			t.Fatalf("ApproveBreakGlassRequest request=%#v err=%v", request, err)
		}
		if relationships, err := mongoStore.ListRelationshipsForUser(ctx, "usr_1", models.RolePatient); err != nil || len(relationships) != 1 || relationships[0].ID != "rel_1" {
			t.Fatalf("ListRelationshipsForUser relationships=%#v err=%v", relationships, err)
		}
		if records, err := mongoStore.ListClinicalRecords(ctx, "usr_1"); err != nil || len(records) != 1 || records[0].ID != "clin_1" {
			t.Fatalf("ListClinicalRecords records=%#v err=%v", records, err)
		}
		if medications, err := mongoStore.ListMedications(ctx, "usr_1"); err != nil || len(medications) != 1 || medications[0].ID != "med_1" {
			t.Fatalf("ListMedications medications=%#v err=%v", medications, err)
		}
		if devices, err := mongoStore.ListDevices(ctx, "usr_1"); err != nil || len(devices) != 1 || devices[0].ID != "dev_1" {
			t.Fatalf("ListDevices devices=%#v err=%v", devices, err)
		}
		if reports, err := mongoStore.ListReports(ctx, "usr_1"); err != nil || len(reports) != 1 || reports[0].ID != "rep_1" {
			t.Fatalf("ListReports reports=%#v err=%v", reports, err)
		}
		if notifications, err := mongoStore.ListNotifications(ctx, "usr_1"); err != nil || len(notifications) != 1 || notifications[0].ID != "not_1" {
			t.Fatalf("ListNotifications notifications=%#v err=%v", notifications, err)
		}
		if tickets, err := mongoStore.ListSupportTickets(ctx, "usr_1"); err != nil || len(tickets) != 1 || tickets[0].ID != "sup_1" {
			t.Fatalf("ListSupportTickets tickets=%#v err=%v", tickets, err)
		}
	})
}

func TestMongoAuthFlowMethodsWithMockDeployment(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock).CreateClient(true).CreateCollection(false))
	ctx := context.Background()
	now := time.Now().UTC()
	mt.Run("auth flows", func(mt *mtest.T) {
		mongoStore := &Mongo{client: mt.Client, db: mt.Client.Database("healthos")}
		userDoc := bson.D{
			{Key: "_id", Value: "usr_1"},
			{Key: "email", Value: "u@example.com"},
			{Key: "verification_token", Value: "vtok"},
			{Key: "email_verified", Value: true},
			{Key: "two_factor_code", Value: "123456"},
			{Key: "failed_login_attempts", Value: 2},
			{Key: "password_reset_token", Value: "prtok"},
		}
		deviceDoc := bson.D{
			{Key: "_id", Value: "dev_1"},
			{Key: "owner_id", Value: "usr_1"},
			{Key: "type", Value: "wearable"},
			{Key: "status", Value: "active"},
		}
		mt.AddMockResponses(
			mtest.CreateCursorResponse(0, "healthos.users", mtest.FirstBatch, userDoc),
			mtest.CreateSuccessResponse(bson.E{Key: "value", Value: userDoc}),
			mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}),
			mtest.CreateSuccessResponse(bson.E{Key: "value", Value: userDoc}),
			mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}),
			mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}),
			mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}),
			mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}),
			mtest.CreateCursorResponse(0, "healthos.users", mtest.FirstBatch, userDoc),
			mtest.CreateSuccessResponse(bson.E{Key: "value", Value: userDoc}),
			mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}),
			mtest.CreateCursorResponse(0, "healthos.devices", mtest.FirstBatch, deviceDoc),
			mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 2}),
			mtest.CreateSuccessResponse(),
		)

		if user, err := mongoStore.FindUserByVerificationToken(ctx, "vtok"); err != nil || user.ID != "usr_1" {
			t.Fatalf("FindUserByVerificationToken user=%#v err=%v", user, err)
		}
		if user, err := mongoStore.VerifyUserEmail(ctx, "vtok"); err != nil || user.ID != "usr_1" {
			t.Fatalf("VerifyUserEmail user=%#v err=%v", user, err)
		}
		if err := mongoStore.SetUserTwoFactorCode(ctx, "usr_1", "654321", now.Add(time.Minute)); err != nil {
			t.Fatalf("SetUserTwoFactorCode returned error: %v", err)
		}
		if user, err := mongoStore.VerifyUserTwoFactorCode(ctx, "u@example.com", "654321"); err != nil || user.ID != "usr_1" {
			t.Fatalf("VerifyUserTwoFactorCode user=%#v err=%v", user, err)
		}
		if err := mongoStore.ClearUserTwoFactorCode(ctx, "usr_1"); err != nil {
			t.Fatalf("ClearUserTwoFactorCode returned error: %v", err)
		}
		if err := mongoStore.UpdateUserFailedLogins(ctx, "usr_1", 3, nil); err != nil {
			t.Fatalf("UpdateUserFailedLogins returned error: %v", err)
		}
		if err := mongoStore.ResetUserFailedLogins(ctx, "usr_1"); err != nil {
			t.Fatalf("ResetUserFailedLogins returned error: %v", err)
		}
		if err := mongoStore.SetUserPasswordResetToken(ctx, "usr_1", "prtok", now.Add(30*time.Minute)); err != nil {
			t.Fatalf("SetUserPasswordResetToken returned error: %v", err)
		}
		if user, err := mongoStore.FindUserByPasswordResetToken(ctx, "prtok"); err != nil || user.ID != "usr_1" {
			t.Fatalf("FindUserByPasswordResetToken user=%#v err=%v", user, err)
		}
		if user, err := mongoStore.ResetUserPassword(ctx, "prtok", "hash"); err != nil || user.ID != "usr_1" {
			t.Fatalf("ResetUserPassword user=%#v err=%v", user, err)
		}
		if err := mongoStore.UpdateUserHealthProfile(ctx, "usr_1", models.HealthProfile{BloodType: "O+"}); err != nil {
			t.Fatalf("UpdateUserHealthProfile returned error: %v", err)
		}
		if device, err := mongoStore.FindDeviceByID(ctx, "dev_1"); err != nil || device.OwnerID != "usr_1" {
			t.Fatalf("FindDeviceByID device=%#v err=%v", device, err)
		}
		if err := mongoStore.DeleteSessionsByUserID(ctx, "usr_1"); err != nil {
			t.Fatalf("DeleteSessionsByUserID returned error: %v", err)
		}
		if err := mongoStore.Ping(ctx); err != nil {
			t.Fatalf("Ping returned error: %v", err)
		}
	})
}

func TestEnsureIndexesWithMockDeployment(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock).CreateClient(true).CreateCollection(false))
	ctx := context.Background()
	mt.Run("creates collections and indexes", func(mt *mtest.T) {
		mongoStore := &Mongo{client: mt.Client, db: mt.Client.Database("healthos")}
		responses := make([]bson.D, 0, 64)
		emptyList := func() bson.D {
			return mtest.CreateCursorResponse(0, "healthos.$cmd.listCollections", mtest.FirstBatch)
		}
		responses = append(responses, emptyList(), mtest.CreateSuccessResponse())
		for range []string{
			"users",
			"sessions",
			"health_alerts",
			"clinical_records",
			"medications",
			"medication_logs",
			"devices",
			"device_transfer_requests",
			"consents",
			"audit_logs",
			"subscriptions",
			"reports",
			"notifications",
			"support_tickets",
			"relationships",
			"break_glass_requests",
			"device_sync_configs",
			"ml_drift_events",
		} {
			responses = append(responses, emptyList(), mtest.CreateSuccessResponse())
		}
		for i := 0; i < 19; i++ {
			responses = append(responses, mtest.CreateSuccessResponse(bson.E{Key: "numIndexesBefore", Value: 1}, bson.E{Key: "numIndexesAfter", Value: 2}))
		}
		mt.AddMockResponses(responses...)

		if err := mongoStore.EnsureIndexes(ctx); err != nil {
			t.Fatalf("EnsureIndexes returned error: %v", err)
		}
	})
}

func TestCollectionExistsBranchesWithMockDeployment(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock).CreateClient(true).CreateCollection(false))
	ctx := context.Background()
	mt.Run("existing collections skip create", func(mt *mtest.T) {
		mongoStore := &Mongo{client: mt.Client, db: mt.Client.Database("healthos")}
		existing := mtest.CreateCursorResponse(0, "healthos.$cmd.listCollections", mtest.FirstBatch, bson.D{{Key: "name", Value: "users"}})
		mt.AddMockResponses(existing, existing)

		if err := mongoStore.createCollectionIfMissing(ctx, "users"); err != nil {
			t.Fatalf("createCollectionIfMissing returned error: %v", err)
		}
		if err := mongoStore.createTimeSeriesIfMissing(ctx); err != nil {
			t.Fatalf("createTimeSeriesIfMissing returned error: %v", err)
		}
	})
}

func mustPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	fn()
}

func TestPreferencesAndNewStoreMethodsWithMockDeployment(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock).CreateClient(true).CreateCollection(false))
	ctx := context.Background()

	mt.Run("GetUserPreferences default and found", func(mt *mtest.T) {
		mongoStore := &Mongo{client: mt.Client, db: mt.Client.Database("healthos")}

		// Mock 1: user with preferences
		userDoc := bson.D{
			{Key: "_id", Value: "usr_1"},
			{Key: "preferences", Value: bson.D{
				{Key: "theme", Value: "dark"},
				{Key: "language", Value: "es"},
			}},
		}
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "healthos.users", mtest.FirstBatch, userDoc))

		prefs, err := mongoStore.GetUserPreferences(ctx, "usr_1")
		if err != nil {
			t.Fatalf("GetUserPreferences failed: %v", err)
		}
		if prefs.Theme != "dark" {
			t.Fatalf("expected dark theme, got %s", prefs.Theme)
		}
	})

	mt.Run("UpdateUserPreferences and UpdateCaregiverProfile", func(mt *mtest.T) {
		mongoStore := &Mongo{client: mt.Client, db: mt.Client.Database("healthos")}

		mt.AddMockResponses(mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}, bson.E{Key: "nModified", Value: 1}))
		err := mongoStore.UpdateUserPreferences(ctx, "usr_1", models.UserPreferences{Theme: "light", Language: "en"})
		if err != nil {
			t.Fatalf("UpdateUserPreferences failed: %v", err)
		}

		mt.AddMockResponses(mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}, bson.E{Key: "nModified", Value: 1}))
		err = mongoStore.UpdateCaregiverProfile(ctx, "cg_1", models.CaregiverProfile{Phone: "12345", Specialty: "Geriatrics"})
		if err != nil {
			t.Fatalf("UpdateCaregiverProfile failed: %v", err)
		}
	})

	mt.Run("DeviceSyncConfig Get and Update", func(mt *mtest.T) {
		mongoStore := &Mongo{client: mt.Client, db: mt.Client.Database("healthos")}

		configDoc := bson.D{
			{Key: "_id", Value: "dev_100"},
			{Key: "sampling_interval_ms", Value: int32(2000)},
			{Key: "batch_size", Value: int32(25)},
		}
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "healthos.device_sync_configs", mtest.FirstBatch, configDoc))

		cfg, err := mongoStore.GetDeviceSyncConfig(ctx, "dev_100")
		if err != nil {
			t.Fatalf("GetDeviceSyncConfig failed: %v", err)
		}
		if cfg.SamplingIntervalMs != 2000 {
			t.Fatalf("expected 2000ms, got %d", cfg.SamplingIntervalMs)
		}

		mt.AddMockResponses(mtest.CreateSuccessResponse(bson.E{Key: "n", Value: 1}, bson.E{Key: "nModified", Value: 1}))
		err = mongoStore.UpdateDeviceSyncConfig(ctx, models.DeviceSyncConfig{DeviceID: "dev_100", SamplingIntervalMs: 500})
		if err != nil {
			t.Fatalf("UpdateDeviceSyncConfig failed: %v", err)
		}
	})

	mt.Run("MLDriftEvent Record and GetLatest", func(mt *mtest.T) {
		mongoStore := &Mongo{client: mt.Client, db: mt.Client.Database("healthos")}

		mt.AddMockResponses(mtest.CreateSuccessResponse())
		err := mongoStore.RecordMLDriftEvent(ctx, models.MLDriftEvent{
			ID:                "drf_1",
			ModelName:         "risk_score",
			Metric:            "psi",
			CurrentDriftScore: 0.28,
			Threshold:         0.25,
			Status:            "model_paused",
			TriggeredAt:       time.Now().UTC(),
		})
		if err != nil {
			t.Fatalf("RecordMLDriftEvent failed: %v", err)
		}

		driftDoc := bson.D{
			{Key: "_id", Value: "drf_1"},
			{Key: "model_name", Value: "risk_score"},
			{Key: "metric", Value: "psi"},
			{Key: "current_drift_score", Value: 0.28},
			{Key: "threshold", Value: 0.25},
			{Key: "status", Value: "model_paused"},
			{Key: "triggered_at", Value: time.Now().UTC()},
		}
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "healthos.ml_drift_events", mtest.FirstBatch, driftDoc))
		latest, err := mongoStore.GetLatestMLDriftEvent(ctx, "risk_score")
		if err != nil {
			t.Fatalf("GetLatestMLDriftEvent failed: %v", err)
		}
		if latest.Status != "model_paused" {
			t.Fatalf("expected model_paused, got %s", latest.Status)
		}
	})

	mt.Run("CalculateMedicationAdherence", func(mt *mtest.T) {
		mongoStore := &Mongo{client: mt.Client, db: mt.Client.Database("healthos")}

		count1 := mtest.CreateCursorResponse(1, "healthos.medication_logs", mtest.FirstBatch, bson.D{{Key: "n", Value: int32(10)}})
		count2 := mtest.CreateCursorResponse(1, "healthos.medication_logs", mtest.FirstBatch, bson.D{{Key: "n", Value: int32(9)}})
		mt.AddMockResponses(count1, count2)

		adh, err := mongoStore.CalculateMedicationAdherence(ctx, "pat_1", "med_1")
		if err != nil {
			t.Fatalf("CalculateMedicationAdherence failed: %v", err)
		}
		if adh != 90.0 {
			t.Fatalf("expected 90.0%% adherence, got %.2f", adh)
		}
	})
}

