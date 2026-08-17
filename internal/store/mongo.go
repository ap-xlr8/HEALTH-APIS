package store

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"healthos/backend/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/event"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var ErrNotFound = errors.New("not found")

type Mongo struct {
	client *mongo.Client
	db     *mongo.Database
}

func NewMongo(ctx context.Context, uri, database string) (*Mongo, error) {
	opts := options.Client().
		ApplyURI(uri).
		SetMonitor(auditLogCommandMonitor()).
		SetServerSelectionTimeout(10 * time.Second).
		SetConnectTimeout(5 * time.Second)

	var client *mongo.Client
	err := connectWithRetry(ctx, 15*time.Second, 500*time.Millisecond, 4*time.Second, func(ctx context.Context) error {
		c, err := mongo.Connect(ctx, opts)
		if err != nil {
			return err
		}
		if err := c.Ping(ctx, nil); err != nil {
			_ = c.Disconnect(context.Background())
			return err
		}
		client = c
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &Mongo{client: client, db: client.Database(database)}, nil
}

// connectWithRetry runs fn until it succeeds, the deadline elapses, or ctx is cancelled,
// sleeping an exponentially growing backoff between attempts so transient Mongo outages
// do not crash the service at startup.
func connectWithRetry(ctx context.Context, deadline time.Duration, initialBackoff, maxBackoff time.Duration, fn func(context.Context) error) error {
	connectCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	backoff := initialBackoff
	for attempt := 1; ; attempt++ {
		err := fn(connectCtx)
		if err == nil {
			return nil
		}
		slog.Warn("mongo_connect_attempt_failed", "attempt", attempt, "error", err, "retry_in", backoff)
		select {
		case <-connectCtx.Done():
			return connectCtx.Err()
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
		}
	}
}

func auditLogCommandMonitor() *event.CommandMonitor {
	return &event.CommandMonitor{
		Started: func(ctx context.Context, evt *event.CommandStartedEvent) {
			if forbiddenAuditMutation(evt) {
				slog.ErrorContext(ctx, "audit_log_mutation_attempt",
					"command", evt.CommandName,
					"database", evt.DatabaseName,
					"request_id", evt.RequestID,
				)
			}
		},
	}
}

func forbiddenAuditMutation(evt *event.CommandStartedEvent) bool {
	if evt == nil {
		return false
	}
	command := strings.ToLower(evt.CommandName)
	switch command {
	case "update", "delete", "findandmodify":
	default:
		return false
	}
	collectionKey := command
	if command == "findandmodify" {
		collectionKey = "findAndModify"
	}
	value := evt.Command.Lookup(collectionKey)
	if value.Type != bsontype.String {
		return false
	}
	return value.StringValue() == "audit_logs"
}

func (m *Mongo) Close(ctx context.Context) error {
	return m.client.Disconnect(ctx)
}

func (m *Mongo) EnsureIndexes(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	if err := m.createCollections(ctx); err != nil {
		return err
	}

	indexes := map[string][]mongo.IndexModel{
		"users": {
			{Keys: bson.D{{Key: "email", Value: 1}}, Options: options.Index().SetUnique(true)},
			{Keys: bson.D{{Key: "role", Value: 1}}},
			{Keys: bson.D{{Key: "verification_token", Value: 1}}, Options: options.Index().SetSparse(true)},
			{Keys: bson.D{{Key: "password_reset_token", Value: 1}}, Options: options.Index().SetSparse(true)},
		},
		"sessions": {
			{Keys: bson.D{{Key: "user_id", Value: 1}}},
			{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
		},
		"health_measurements": {
			{Keys: bson.D{{Key: "patient_id", Value: 1}, {Key: "timestamp", Value: -1}}},
			{Keys: bson.D{{Key: "device_id", Value: 1}}},
		},
		"health_alerts": {
			{Keys: bson.D{{Key: "patient_id", Value: 1}, {Key: "created_at", Value: -1}}},
			{Keys: bson.D{{Key: "patient_id", Value: 1}, {Key: "acknowledged", Value: 1}, {Key: "created_at", Value: -1}}},
		},
		"relationships": {
			{Keys: bson.D{{Key: "caregiver_id", Value: 1}, {Key: "patient_id", Value: 1}}, Options: options.Index().SetUnique(true)},
			{Keys: bson.D{{Key: "caregiver_id", Value: 1}, {Key: "patient_id", Value: 1}, {Key: "status", Value: 1}}},
		},
		"consents": {
			{Keys: bson.D{{Key: "patient_id", Value: 1}, {Key: "caregiver_id", Value: 1}, {Key: "revoked", Value: 1}}},
		},
		"audit_logs": {
			{Keys: bson.D{{Key: "created_at", Value: -1}}},
			{Keys: bson.D{{Key: "user_id", Value: 1}}},
		},
		"subscriptions": {
			{Keys: bson.D{{Key: "stripe_event_id", Value: 1}}, Options: options.Index().SetUnique(true)},
			{Keys: bson.D{{Key: "stripe_customer_id", Value: 1}}},
			{Keys: bson.D{{Key: "stripe_subscription_id", Value: 1}}},
		},
		"clinical_records": {
			{Keys: bson.D{{Key: "patient_id", Value: 1}}},
		},
		"medications": {
			{Keys: bson.D{{Key: "patient_id", Value: 1}, {Key: "active", Value: 1}}},
		},
		"medication_logs": {
			{Keys: bson.D{{Key: "patient_id", Value: 1}, {Key: "taken_at", Value: -1}}},
		},
		"devices": {
			{Keys: bson.D{{Key: "owner_id", Value: 1}}},
			{Keys: bson.D{{Key: "serial_number", Value: 1}}, Options: options.Index().SetUnique(true).SetSparse(true)},
		},
		"device_transfer_requests": {
			{Keys: bson.D{{Key: "device_id", Value: 1}, {Key: "status", Value: 1}}},
		},
		"reports": {
			{Keys: bson.D{{Key: "patient_id", Value: 1}, {Key: "created_at", Value: -1}}},
		},
		"notifications": {
			{Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "created_at", Value: -1}}},
		},
		"support_tickets": {
			{Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "status", Value: 1}}},
		},
		"break_glass_requests": {
			{Keys: bson.D{{Key: "requester_id", Value: 1}, {Key: "status", Value: 1}}},
			{Keys: bson.D{{Key: "expires_at", Value: 1}}},
		},
		"device_sync_configs": {
			{Keys: bson.D{{Key: "_id", Value: 1}}},
		},
		"ml_drift_events": {
			{Keys: bson.D{{Key: "model_name", Value: 1}, {Key: "triggered_at", Value: -1}}},
		},
	}

	for collection, models := range indexes {
		if len(models) == 0 {
			continue
		}
		if _, err := m.db.Collection(collection).Indexes().CreateMany(ctx, models); err != nil {
			return err
		}
	}
	return nil
}

func (m *Mongo) createCollections(ctx context.Context) error {
	if err := m.createTimeSeriesIfMissing(ctx); err != nil {
		return err
	}
	for _, name := range []string{
		"users",
		"sessions",
		"health_alerts",
		"clinical_records",
		"medications",
		"medication_logs",
		"devices",
		"device_sync_configs",
		"device_transfer_requests",
		"consents",
		"audit_logs",
		"subscriptions",
		"reports",
		"notifications",
		"support_tickets",
		"relationships",
		"break_glass_requests",
		"ml_drift_events",
	} {
		if err := m.createCollectionIfMissing(ctx, name); err != nil {
			return err
		}
	}
	return nil
}

func (m *Mongo) createCollectionIfMissing(ctx context.Context, name string) error {
	names, err := m.db.ListCollectionNames(ctx, bson.M{"name": name})
	if err != nil {
		return err
	}
	if len(names) > 0 {
		return nil
	}
	return m.db.CreateCollection(ctx, name)
}

func (m *Mongo) createTimeSeriesIfMissing(ctx context.Context) error {
	names, err := m.db.ListCollectionNames(ctx, bson.M{"name": "health_measurements"})
	if err != nil {
		return err
	}
	if len(names) > 0 {
		return nil
	}
	opts := options.CreateCollection().SetTimeSeriesOptions(options.TimeSeries().
		SetTimeField("timestamp").
		SetMetaField("patient_id").
		SetGranularity("minutes"))
	return m.db.CreateCollection(ctx, "health_measurements", opts)
}

func (m *Mongo) CreateUser(ctx context.Context, user models.User) error {
	_, err := m.db.Collection("users").InsertOne(ctx, user)
	return err
}

func (m *Mongo) FindUserByEmail(ctx context.Context, email string) (models.User, error) {
	var user models.User
	err := m.db.Collection("users").FindOne(ctx, bson.M{"email": email}).Decode(&user)
	return user, normalizeFindErr(err)
}

func (m *Mongo) FindUserByID(ctx context.Context, id string) (models.User, error) {
	var user models.User
	err := m.db.Collection("users").FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	return user, normalizeFindErr(err)
}

func (m *Mongo) CreateSession(ctx context.Context, session models.Session) error {
	_, err := m.db.Collection("sessions").InsertOne(ctx, session)
	return err
}

func (m *Mongo) FindSessionByID(ctx context.Context, id string) (models.Session, error) {
	var session models.Session
	err := m.db.Collection("sessions").FindOne(ctx, bson.M{"_id": id}).Decode(&session)
	return session, normalizeFindErr(err)
}

func (m *Mongo) DeleteSessionByID(ctx context.Context, id string) error {
	_, err := m.db.Collection("sessions").DeleteOne(ctx, bson.M{"_id": id})
	return err
}

func (m *Mongo) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	_, err := m.db.Collection("sessions").DeleteMany(ctx, bson.M{"user_id": userID})
	return err
}

func (m *Mongo) InsertMeasurements(ctx context.Context, measurements []models.Measurement) error {
	if len(measurements) == 0 {
		return nil
	}
	docs := make([]any, 0, len(measurements))
	for _, measurement := range measurements {
		docs = append(docs, measurement)
	}
	_, err := m.db.Collection("health_measurements").InsertMany(ctx, docs)
	return err
}

func (m *Mongo) ListMeasurements(ctx context.Context, filter models.MeasurementFilter) ([]models.Measurement, error) {
	query := bson.M{"patient_id": filter.PatientID}
	if filter.Type != "" {
		query["type"] = filter.Type
	}
	timeRange := bson.M{}
	if !filter.From.IsZero() {
		timeRange["$gte"] = filter.From
	}
	if !filter.To.IsZero() {
		timeRange["$lte"] = filter.To
	}
	if len(timeRange) > 0 {
		query["timestamp"] = timeRange
	}
	limit := filter.Limit
	if limit == 0 {
		limit = 100
	}
	cursor, err := m.db.Collection("health_measurements").Find(ctx, query, options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}).
		SetLimit(limit))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var measurements []models.Measurement
	if err := cursor.All(ctx, &measurements); err != nil {
		return nil, err
	}
	if measurements == nil {
		measurements = []models.Measurement{}
	}
	return measurements, nil
}

func (m *Mongo) CreateAlert(ctx context.Context, alert models.Alert) error {
	_, err := m.db.Collection("health_alerts").InsertOne(ctx, alert)
	return err
}

func (m *Mongo) FindAlertByID(ctx context.Context, id string) (models.Alert, error) {
	var alert models.Alert
	err := m.db.Collection("health_alerts").FindOne(ctx, bson.M{"_id": id}).Decode(&alert)
	return alert, normalizeFindErr(err)
}

func (m *Mongo) AcknowledgeAlert(ctx context.Context, id string) (models.Alert, error) {
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var alert models.Alert
	err := m.db.Collection("health_alerts").FindOneAndUpdate(
		ctx,
		bson.M{"_id": id},
		bson.M{"$set": bson.M{"acknowledged": true}},
		opts,
	).Decode(&alert)
	return alert, normalizeFindErr(err)
}

func (m *Mongo) ListAlerts(ctx context.Context, patientID string) ([]models.Alert, error) {
	filter := bson.M{}
	if strings.TrimSpace(patientID) != "" {
		filter["patient_id"] = strings.TrimSpace(patientID)
	}
	findOpts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(100)
	cursor, err := m.db.Collection("health_alerts").Find(ctx, filter, findOpts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var alerts []models.Alert
	if err := cursor.All(ctx, &alerts); err != nil {
		return nil, err
	}
	if alerts == nil {
		alerts = []models.Alert{}
	}
	return alerts, nil
}

func (m *Mongo) HasActiveRelationship(ctx context.Context, caregiverID, patientID string) (bool, error) {
	count, err := m.db.Collection("relationships").CountDocuments(ctx, bson.M{
		"caregiver_id": caregiverID,
		"patient_id":   patientID,
		"status":       "active",
	})
	return count > 0, err
}

func (m *Mongo) UpsertRelationship(ctx context.Context, relationship models.Relationship) error {
	_, err := m.db.Collection("relationships").UpdateOne(
		ctx,
		bson.M{
			"caregiver_id": relationship.CaregiverID,
			"patient_id":   relationship.PatientID,
		},
		bson.M{
			"$set": bson.M{
				"status":     relationship.Status,
				"updated_at": relationship.UpdatedAt,
			},
			"$setOnInsert": bson.M{
				"_id":          relationship.ID,
				"caregiver_id": relationship.CaregiverID,
				"patient_id":   relationship.PatientID,
				"created_at":   relationship.CreatedAt,
			},
		},
		options.Update().SetUpsert(true),
	)
	return err
}

func (m *Mongo) ListRelationshipsForUser(ctx context.Context, userID, role string) ([]models.Relationship, error) {
	filter := bson.M{}
	switch role {
	case models.RolePatient:
		filter = bson.M{"patient_id": userID}
	case models.RoleCaregiver:
		filter = bson.M{"caregiver_id": userID}
	case models.RoleAdmin:
		filter = bson.M{}
	default:
		filter = bson.M{"_id": "__none__"}
	}
	cursor, err := m.db.Collection("relationships").Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var relationships []models.Relationship
	if err := cursor.All(ctx, &relationships); err != nil {
		return nil, err
	}
	if relationships == nil {
		relationships = []models.Relationship{}
	}
	return relationships, nil
}

func (m *Mongo) HasConsentScope(ctx context.Context, caregiverID, patientID, scope string) (bool, error) {
	count, err := m.db.Collection("consents").CountDocuments(ctx, bson.M{
		"caregiver_id": caregiverID,
		"patient_id":   patientID,
		"revoked":      false,
		"scopes":       scope,
	})
	return count > 0, err
}

func (m *Mongo) UpsertConsent(ctx context.Context, consent models.Consent) error {
	_, err := m.db.Collection("consents").UpdateOne(
		ctx,
		bson.M{
			"patient_id":   consent.PatientID,
			"caregiver_id": consent.CaregiverID,
		},
		bson.M{
			"$set": bson.M{
				"scopes":     consent.Scopes,
				"revoked":    consent.Revoked,
				"updated_at": consent.UpdatedAt,
			},
			"$setOnInsert": bson.M{
				"_id":          consent.ID,
				"patient_id":   consent.PatientID,
				"caregiver_id": consent.CaregiverID,
				"created_at":   consent.CreatedAt,
			},
		},
		options.Update().SetUpsert(true),
	)
	return err
}

func (m *Mongo) WriteAudit(ctx context.Context, log models.AuditLog) error {
	_, err := m.db.Collection("audit_logs").InsertOne(ctx, log)
	return err
}

func (m *Mongo) CreateClinicalRecord(ctx context.Context, record models.ClinicalRecord) error {
	_, err := m.db.Collection("clinical_records").InsertOne(ctx, record)
	return err
}

func (m *Mongo) ListClinicalRecords(ctx context.Context, patientID string) ([]models.ClinicalRecord, error) {
	cursor, err := m.db.Collection("clinical_records").Find(ctx, bson.M{"patient_id": patientID}, options.Find().SetSort(bson.D{{Key: "recorded_at", Value: -1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var records []models.ClinicalRecord
	if err := cursor.All(ctx, &records); err != nil {
		return nil, err
	}
	if records == nil {
		records = []models.ClinicalRecord{}
	}
	return records, nil
}

func (m *Mongo) CreateMedication(ctx context.Context, medication models.Medication) error {
	_, err := m.db.Collection("medications").InsertOne(ctx, medication)
	return err
}

func (m *Mongo) DeleteMedication(ctx context.Context, patientID, medicationID string) error {
	_, err := m.db.Collection("medications").DeleteOne(ctx, bson.M{"_id": medicationID, "patient_id": patientID})
	return err
}

func (m *Mongo) ListMedications(ctx context.Context, patientID string) ([]models.Medication, error) {
	cursor, err := m.db.Collection("medications").Find(ctx, bson.M{"patient_id": patientID}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var medications []models.Medication
	if err := cursor.All(ctx, &medications); err != nil {
		return nil, err
	}
	if medications == nil {
		medications = []models.Medication{}
	}
	return medications, nil
}

func (m *Mongo) RecordMedicationLog(ctx context.Context, log models.MedicationLog) error {
	_, err := m.db.Collection("medication_logs").InsertOne(ctx, log)
	return err
}

func (m *Mongo) CreateDevice(ctx context.Context, device models.Device) error {
	_, err := m.db.Collection("devices").InsertOne(ctx, device)
	return err
}

func (m *Mongo) ListDevices(ctx context.Context, ownerID string) ([]models.Device, error) {
	cursor, err := m.db.Collection("devices").Find(ctx, bson.M{"owner_id": ownerID}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var devices []models.Device
	if err := cursor.All(ctx, &devices); err != nil {
		return nil, err
	}
	if devices == nil {
		devices = []models.Device{}
	}
	return devices, nil
}

func (m *Mongo) CreateDeviceTransferRequest(ctx context.Context, request models.DeviceTransferRequest) error {
	_, err := m.db.Collection("device_transfer_requests").InsertOne(ctx, request)
	return err
}

func (m *Mongo) FindDeviceTransferRequestByID(ctx context.Context, id string) (models.DeviceTransferRequest, error) {
	var request models.DeviceTransferRequest
	err := m.db.Collection("device_transfer_requests").FindOne(ctx, bson.M{"_id": id}).Decode(&request)
	return request, normalizeFindErr(err)
}

func (m *Mongo) UpdateDeviceTransferRequestStatus(ctx context.Context, id, status string, updatedAt time.Time) (models.DeviceTransferRequest, error) {
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var request models.DeviceTransferRequest
	err := m.db.Collection("device_transfer_requests").FindOneAndUpdate(
		ctx,
		bson.M{"_id": id, "status": "pending"},
		bson.M{"$set": bson.M{"status": status, "updated_at": updatedAt}},
		opts,
	).Decode(&request)
	return request, normalizeFindErr(err)
}

func (m *Mongo) UpdateDeviceOwner(ctx context.Context, id, ownerID string, updatedAt time.Time) error {
	result, err := m.db.Collection("devices").UpdateOne(
		ctx,
		bson.M{"_id": id},
		bson.M{"$set": bson.M{"owner_id": ownerID, "updated_at": updatedAt}},
	)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return ErrNotFound
	}
	return nil
}

func (m *Mongo) CreateReport(ctx context.Context, report models.Report) error {
	_, err := m.db.Collection("reports").InsertOne(ctx, report)
	return err
}

func (m *Mongo) ListReports(ctx context.Context, patientID string) ([]models.Report, error) {
	cursor, err := m.db.Collection("reports").Find(ctx, bson.M{"patient_id": patientID}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var reports []models.Report
	if err := cursor.All(ctx, &reports); err != nil {
		return nil, err
	}
	if reports == nil {
		reports = []models.Report{}
	}
	return reports, nil
}

func (m *Mongo) CreateNotification(ctx context.Context, notification models.Notification) error {
	_, err := m.db.Collection("notifications").InsertOne(ctx, notification)
	return err
}

func (m *Mongo) ListNotifications(ctx context.Context, userID string) ([]models.Notification, error) {
	cursor, err := m.db.Collection("notifications").Find(ctx, bson.M{"user_id": userID}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var notifications []models.Notification
	if err := cursor.All(ctx, &notifications); err != nil {
		return nil, err
	}
	if notifications == nil {
		notifications = []models.Notification{}
	}
	return notifications, nil
}

func (m *Mongo) CreateSupportTicket(ctx context.Context, ticket models.SupportTicket) error {
	_, err := m.db.Collection("support_tickets").InsertOne(ctx, ticket)
	return err
}

func (m *Mongo) ListSupportTickets(ctx context.Context, userID string) ([]models.SupportTicket, error) {
	cursor, err := m.db.Collection("support_tickets").Find(ctx, bson.M{"user_id": userID}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var tickets []models.SupportTicket
	if err := cursor.All(ctx, &tickets); err != nil {
		return nil, err
	}
	if tickets == nil {
		tickets = []models.SupportTicket{}
	}
	return tickets, nil
}

func (m *Mongo) UpsertSubscriptionEvent(ctx context.Context, sub models.Subscription) error {
	_, err := m.db.Collection("subscriptions").UpdateOne(
		ctx,
		bson.M{"stripe_event_id": sub.StripeEventID},
		bson.M{"$setOnInsert": sub},
		options.Update().SetUpsert(true),
	)
	return err
}

func (m *Mongo) CreateBreakGlassRequest(ctx context.Context, request models.BreakGlassRequest) error {
	_, err := m.db.Collection("break_glass_requests").InsertOne(ctx, request)
	return err
}

func (m *Mongo) FindBreakGlassRequestByID(ctx context.Context, id string) (models.BreakGlassRequest, error) {
	var request models.BreakGlassRequest
	err := m.db.Collection("break_glass_requests").FindOne(ctx, bson.M{"_id": id}).Decode(&request)
	return request, normalizeFindErr(err)
}

func (m *Mongo) ApproveBreakGlassRequest(ctx context.Context, id, approverID string, approvedAt time.Time) (models.BreakGlassRequest, error) {
	filter := bson.M{
		"_id":          id,
		"status":       "pending",
		"requester_id": bson.M{"$ne": approverID},
		"expires_at":   bson.M{"$gt": approvedAt},
	}
	update := bson.M{"$set": bson.M{
		"status":      "approved",
		"approver_id": approverID,
		"approved_at": approvedAt,
	}}
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var request models.BreakGlassRequest
	err := m.db.Collection("break_glass_requests").FindOneAndUpdate(ctx, filter, update, opts).Decode(&request)
	return request, normalizeFindErr(err)
}

func (m *Mongo) Ping(ctx context.Context) error {
	return m.client.Ping(ctx, nil)
}

func (m *Mongo) FindDeviceByID(ctx context.Context, id string) (models.Device, error) {
	var device models.Device
	err := m.db.Collection("devices").FindOne(ctx, bson.M{"_id": id}).Decode(&device)
	return device, normalizeFindErr(err)
}

func (m *Mongo) FindUserByVerificationToken(ctx context.Context, token string) (models.User, error) {
	var user models.User
	err := m.db.Collection("users").FindOne(ctx, bson.M{"verification_token": token}).Decode(&user)
	return user, normalizeFindErr(err)
}

func (m *Mongo) VerifyUserEmail(ctx context.Context, token string) (models.User, error) {
	now := time.Now().UTC()
	filter := bson.M{
		"verification_token": token,
		"$or": []bson.M{
			{"verification_expires_at": bson.M{"$exists": false}},
			{"verification_expires_at": nil},
			{"verification_expires_at": bson.M{"$gt": now}},
		},
	}
	update := bson.M{
		"$set": bson.M{
			"email_verified": true,
		},
		"$unset": bson.M{
			"verification_token":      "",
			"verification_expires_at": "",
		},
	}
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var user models.User
	err := m.db.Collection("users").FindOneAndUpdate(ctx, filter, update, opts).Decode(&user)
	return user, normalizeFindErr(err)
}

func (m *Mongo) SetUserTwoFactorCode(ctx context.Context, userID, code string, expiresAt time.Time) error {
	update := bson.M{
		"$set": bson.M{
			"two_factor_code":       code,
			"two_factor_expires_at": expiresAt,
		},
	}
	result, err := m.db.Collection("users").UpdateOne(ctx, bson.M{"_id": userID}, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return ErrNotFound
	}
	return nil
}

func (m *Mongo) VerifyUserTwoFactorCode(ctx context.Context, email, code string) (models.User, error) {
	now := time.Now().UTC()
	filter := bson.M{
		"email":                 strings.ToLower(strings.TrimSpace(email)),
		"two_factor_code":       strings.TrimSpace(code),
		"two_factor_expires_at": bson.M{"$gt": now},
	}
	update := bson.M{
		"$set": bson.M{
			"email_verified": true,
		},
		"$unset": bson.M{
			"two_factor_code":       "",
			"two_factor_expires_at": "",
		},
	}
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var user models.User
	err := m.db.Collection("users").FindOneAndUpdate(ctx, filter, update, opts).Decode(&user)
	return user, normalizeFindErr(err)
}

func (m *Mongo) ClearUserTwoFactorCode(ctx context.Context, userID string) error {
	update := bson.M{
		"$unset": bson.M{
			"two_factor_code":       "",
			"two_factor_expires_at": "",
		},
	}
	_, err := m.db.Collection("users").UpdateOne(ctx, bson.M{"_id": userID}, update)
	return err
}

func (m *Mongo) UpdateUserFailedLogins(ctx context.Context, userID string, attempts int, lockoutUntil *time.Time) error {
	update := bson.M{
		"$set": bson.M{
			"failed_login_attempts": attempts,
			"lockout_until":         lockoutUntil,
		},
	}
	_, err := m.db.Collection("users").UpdateOne(ctx, bson.M{"_id": userID}, update)
	return err
}

func (m *Mongo) ResetUserFailedLogins(ctx context.Context, userID string) error {
	update := bson.M{
		"$set": bson.M{
			"failed_login_attempts": 0,
			"lockout_until":         nil,
		},
	}
	_, err := m.db.Collection("users").UpdateOne(ctx, bson.M{"_id": userID}, update)
	return err
}

func (m *Mongo) SetUserPasswordResetToken(ctx context.Context, userID, token string, expiresAt time.Time) error {
	update := bson.M{
		"$set": bson.M{
			"password_reset_token":      token,
			"password_reset_expires_at": expiresAt,
		},
	}
	_, err := m.db.Collection("users").UpdateOne(ctx, bson.M{"_id": userID}, update)
	return err
}

func (m *Mongo) FindUserByPasswordResetToken(ctx context.Context, token string) (models.User, error) {
	var user models.User
	err := m.db.Collection("users").FindOne(ctx, bson.M{"password_reset_token": token}).Decode(&user)
	return user, normalizeFindErr(err)
}

func (m *Mongo) ResetUserPassword(ctx context.Context, token, passwordHash string) (models.User, error) {
	now := time.Now().UTC()
	filter := bson.M{
		"password_reset_token":      token,
		"password_reset_expires_at": bson.M{"$gt": now},
	}
	update := bson.M{
		"$set": bson.M{
			"password_hash": passwordHash,
		},
		"$unset": bson.M{
			"password_reset_token":      "",
			"password_reset_expires_at": "",
		},
	}
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var user models.User
	err := m.db.Collection("users").FindOneAndUpdate(ctx, filter, update, opts).Decode(&user)
	return user, normalizeFindErr(err)
}

func (m *Mongo) UpdateUserHealthProfile(ctx context.Context, userID string, profile models.HealthProfile) error {
	update := bson.M{
		"$set": bson.M{
			"health_profile": profile,
		},
	}
	_, err := m.db.Collection("users").UpdateOne(ctx, bson.M{"_id": userID}, update)
	return err
}

func (m *Mongo) GetUserPreferences(ctx context.Context, userID string) (models.UserPreferences, error) {
	var user models.User
	err := m.db.Collection("users").FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		return models.UserPreferences{}, normalizeFindErr(err)
	}
	if user.Preferences == nil {
		return models.UserPreferences{
			Theme:                "system",
			Language:             "es",
			NotificationChannels: []string{"push", "email"},
			QuietHours: models.QuietHours{
				Enabled: false,
				Start:   "22:00",
				End:     "07:00",
			},
		}, nil
	}
	return *user.Preferences, nil
}

func (m *Mongo) UpdateUserPreferences(ctx context.Context, userID string, prefs models.UserPreferences) error {
	update := bson.M{
		"$set": bson.M{
			"preferences": prefs,
		},
	}
	_, err := m.db.Collection("users").UpdateOne(ctx, bson.M{"_id": userID}, update)
	return err
}

func (m *Mongo) GetNotificationPreferences(ctx context.Context, userID string) (models.NotificationPreferences, error) {
	var user models.User
	err := m.db.Collection("users").FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		return models.NotificationPreferences{}, normalizeFindErr(err)
	}
	if user.NotificationPreferences == nil {
		return models.NotificationPreferences{
			Channels: models.NotificationChannelPreference{
				Push:  true,
				Email: true,
				SMS:   false,
			},
			AlertTypes: map[string]bool{
				"tachycardia":         true,
				"hypoxemia":           true,
				"sos":                 true,
				"medication_reminder": true,
				"device_status":       true,
			},
		}, nil
	}
	return *user.NotificationPreferences, nil
}

func (m *Mongo) UpdateNotificationPreferences(ctx context.Context, userID string, prefs models.NotificationPreferences) error {
	update := bson.M{
		"$set": bson.M{
			"notification_preferences": prefs,
		},
	}
	_, err := m.db.Collection("users").UpdateOne(ctx, bson.M{"_id": userID}, update)
	return err
}

func (m *Mongo) UpdateCaregiverProfile(ctx context.Context, userID string, profile models.CaregiverProfile) error {
	update := bson.M{
		"$set": bson.M{
			"caregiver_profile": profile,
		},
	}
	_, err := m.db.Collection("users").UpdateOne(ctx, bson.M{"_id": userID}, update)
	return err
}

func (m *Mongo) GetDeviceSyncConfig(ctx context.Context, deviceID string) (models.DeviceSyncConfig, error) {
	var cfg models.DeviceSyncConfig
	err := m.db.Collection("device_sync_configs").FindOne(ctx, bson.M{"_id": deviceID}).Decode(&cfg)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			// Default configuration
			return models.DeviceSyncConfig{
				DeviceID:           deviceID,
				SamplingIntervalMs: 1000,
				BatchSize:          50,
				CriticalThresholds: map[string]float64{
					"heart_rate_max": 140,
					"heart_rate_min": 40,
					"spo2_min":       90,
				},
				UpdatedAt: time.Now().UTC(),
			}, nil
		}
		return models.DeviceSyncConfig{}, err
	}
	return cfg, nil
}

func (m *Mongo) UpdateDeviceSyncConfig(ctx context.Context, config models.DeviceSyncConfig) error {
	opts := options.Update().SetUpsert(true)
	config.UpdatedAt = time.Now().UTC()
	_, err := m.db.Collection("device_sync_configs").UpdateOne(ctx, bson.M{"_id": config.DeviceID}, bson.M{"$set": config}, opts)
	return err
}

func (m *Mongo) CalculateMedicationAdherence(ctx context.Context, patientID, medicationID string) (float64, error) {
	filter := bson.M{"patient_id": patientID}
	if medicationID != "" {
		filter["medication_id"] = medicationID
	}
	totalLogs, err := m.db.Collection("medication_logs").CountDocuments(ctx, filter)
	if err != nil {
		return 0, err
	}
	if totalLogs == 0 {
		return 100.0, nil
	}

	filter["status"] = "taken"
	takenLogs, err := m.db.Collection("medication_logs").CountDocuments(ctx, filter)
	if err != nil {
		return 0, err
	}

	adherence := (float64(takenLogs) / float64(totalLogs)) * 100.0
	return adherence, nil
}

func (m *Mongo) RecordMLDriftEvent(ctx context.Context, event models.MLDriftEvent) error {
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	_, err := m.db.Collection("ml_drift_events").InsertOne(ctx, event)
	return err
}

func (m *Mongo) GetLatestMLDriftEvent(ctx context.Context, modelName string) (models.MLDriftEvent, error) {
	var event models.MLDriftEvent
	opts := options.FindOne().SetSort(bson.D{{Key: "triggered_at", Value: -1}})
	err := m.db.Collection("ml_drift_events").FindOne(ctx, bson.M{"model_name": modelName}, opts).Decode(&event)
	return event, normalizeFindErr(err)
}

func (m *Mongo) ListUsers(ctx context.Context, role, status string, limit int64) ([]models.User, error) {
	filter := bson.M{}
	if role != "" {
		filter["role"] = role
	}
	if status != "" {
		filter["status"] = status
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	opts := options.Find().SetLimit(limit).SetSort(bson.D{{Key: "created_at", Value: -1}})
	cursor, err := m.db.Collection("users").Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var users []models.User
	if err := cursor.All(ctx, &users); err != nil {
		return nil, err
	}
	if users == nil {
		users = []models.User{}
	}
	return users, nil
}

func (m *Mongo) UpdateUserStatus(ctx context.Context, userID, status string) error {
	res, err := m.db.Collection("users").UpdateOne(ctx, bson.M{"_id": userID}, bson.M{"$set": bson.M{"status": status}})
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return ErrNotFound
	}
	return nil
}

func (m *Mongo) ListAuditLogs(ctx context.Context, userID, action string, limit int64) ([]models.AuditLog, error) {
	filter := bson.M{}
	if userID != "" {
		filter["user_id"] = userID
	}
	if action != "" {
		filter["action"] = action
	}
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	opts := options.Find().SetLimit(limit).SetSort(bson.D{{Key: "created_at", Value: -1}})
	cursor, err := m.db.Collection("audit_logs").Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var logs []models.AuditLog
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, err
	}
	if logs == nil {
		logs = []models.AuditLog{}
	}
	return logs, nil
}

func (m *Mongo) ListConsents(ctx context.Context, patientID, caregiverID string) ([]models.Consent, error) {
	filter := bson.M{"revoked": false}
	if patientID != "" {
		filter["patient_id"] = patientID
	}
	if caregiverID != "" {
		filter["caregiver_id"] = caregiverID
	}
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})
	cursor, err := m.db.Collection("consents").Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var consents []models.Consent
	if err := cursor.All(ctx, &consents); err != nil {
		return nil, err
	}
	if consents == nil {
		consents = []models.Consent{}
	}
	return consents, nil
}

func normalizeFindErr(err error) error {
	if errors.Is(err, mongo.ErrNoDocuments) {
		return ErrNotFound
	}
	return err
}
