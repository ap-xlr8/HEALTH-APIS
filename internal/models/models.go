package models

import "time"

const (
	RolePatient   = "patient"
	RoleCaregiver = "caregiver"
	RoleAdmin     = "admin"

	ScopeReadMeasurements  = "read:measurements"
	ScopeReadPatient       = "read:patient"
	ScopeReadAlerts        = "read:alerts"
	ScopeWriteMeasurements = "write:measurements"
	ScopeWriteClinical     = "write:clinical"
	ScopeWriteMedications  = "write:medications"
	ScopeWriteReports      = "write:reports"
	ScopeWriteConsent      = "write:consent"
	ScopeWriteDevices      = "write:devices"
	ScopeWritePatient      = "write:patient"
)

type User struct {
	ID                    string     `bson:"_id" json:"id"`
	Email                 string     `bson:"email" json:"email"`
	PasswordHash          string     `bson:"password_hash" json:"-"`
	Role                  string     `bson:"role" json:"role"`
	FirstName             string     `bson:"first_name" json:"first_name"`
	LastName              string     `bson:"last_name" json:"last_name"`
	Age                   int        `bson:"age,omitempty" json:"age,omitempty"`
	HealthProfile         any        `bson:"health_profile,omitempty" json:"health_profile,omitempty"`
	ActiveConditions      []string   `bson:"active_conditions,omitempty" json:"active_conditions,omitempty"`
	EmailVerified         bool       `bson:"email_verified" json:"email_verified"`
	VerificationToken     string     `bson:"verification_token,omitempty" json:"-"`
	VerificationExpiresAt *time.Time `bson:"verification_expires_at,omitempty" json:"-"`
	FailedLoginAttempts   int        `bson:"failed_login_attempts,omitempty" json:"-"`
	LockoutUntil          *time.Time `bson:"lockout_until,omitempty" json:"-"`
	CreatedAt             time.Time  `bson:"created_at" json:"created_at"`
}

type Session struct {
	ID        string    `bson:"_id"`
	UserID    string    `bson:"user_id"`
	Kind      string    `bson:"kind"`
	ExpiresAt time.Time `bson:"expires_at"`
	CreatedAt time.Time `bson:"created_at"`
}

type Measurement struct {
	ID        string    `bson:"_id" json:"id"`
	PatientID string    `bson:"patient_id" json:"patient_id"`
	DeviceID  string    `bson:"device_id" json:"device_id"`
	Type      string    `bson:"type" json:"type"`
	Value     float64   `bson:"value" json:"value"`
	Unit      string    `bson:"unit" json:"unit"`
	Timestamp time.Time `bson:"timestamp" json:"timestamp"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
}

type MeasurementFilter struct {
	PatientID string
	Type      string
	From      time.Time
	To        time.Time
	Limit     int64
}

type Alert struct {
	ID             string    `bson:"_id" json:"id"`
	PatientID      string    `bson:"patient_id" json:"patient_id"`
	Type           string    `bson:"type" json:"type"`
	Severity       string    `bson:"severity" json:"severity"`
	Message        string    `bson:"message" json:"message"`
	MeasurementRef string    `bson:"measurement_ref" json:"measurement_ref"`
	Acknowledged   bool      `bson:"acknowledged" json:"acknowledged"`
	CreatedAt      time.Time `bson:"created_at" json:"created_at"`
}

type Relationship struct {
	ID          string    `bson:"_id" json:"id"`
	CaregiverID string    `bson:"caregiver_id" json:"caregiver_id"`
	PatientID   string    `bson:"patient_id" json:"patient_id"`
	Status      string    `bson:"status" json:"status"`
	CreatedAt   time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time `bson:"updated_at" json:"updated_at"`
}

type Consent struct {
	ID          string    `bson:"_id"`
	PatientID   string    `bson:"patient_id"`
	CaregiverID string    `bson:"caregiver_id"`
	Scopes      []string  `bson:"scopes"`
	Revoked     bool      `bson:"revoked"`
	CreatedAt   time.Time `bson:"created_at"`
	UpdatedAt   time.Time `bson:"updated_at"`
}

type AuditLog struct {
	ID        string         `bson:"_id" json:"id"`
	UserID    string         `bson:"user_id" json:"user_id"`
	Action    string         `bson:"action" json:"action"`
	Resource  string         `bson:"resource" json:"resource"`
	Allowed   bool           `bson:"allowed" json:"allowed"`
	Reason    string         `bson:"reason,omitempty" json:"reason,omitempty"`
	Metadata  map[string]any `bson:"metadata,omitempty" json:"metadata,omitempty"`
	CreatedAt time.Time      `bson:"created_at" json:"created_at"`
}

type Subscription struct {
	ID               string    `bson:"_id" json:"id"`
	StripeEventID    string    `bson:"stripe_event_id" json:"stripe_event_id"`
	StripeCustomerID string    `bson:"stripe_customer_id,omitempty" json:"stripe_customer_id,omitempty"`
	StripeSubID      string    `bson:"stripe_subscription_id,omitempty" json:"stripe_subscription_id,omitempty"`
	Status           string    `bson:"status" json:"status"`
	RawEvent         any       `bson:"raw_event" json:"raw_event"`
	CreatedAt        time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt        time.Time `bson:"updated_at" json:"updated_at"`
}

type BreakGlassRequest struct {
	ID          string    `bson:"_id" json:"id"`
	RequesterID string    `bson:"requester_id" json:"requester_id"`
	ApproverID  string    `bson:"approver_id,omitempty" json:"approver_id,omitempty"`
	Reason      string    `bson:"reason" json:"reason"`
	Status      string    `bson:"status" json:"status"`
	ExpiresAt   time.Time `bson:"expires_at" json:"expires_at"`
	CreatedAt   time.Time `bson:"created_at" json:"created_at"`
	ApprovedAt  time.Time `bson:"approved_at,omitempty" json:"approved_at,omitempty"`
}

type ClinicalRecord struct {
	ID         string    `bson:"_id" json:"id"`
	PatientID  string    `bson:"patient_id" json:"patient_id"`
	Conditions []string  `bson:"conditions" json:"conditions"`
	Allergies  []string  `bson:"allergies" json:"allergies"`
	Notes      string    `bson:"notes,omitempty" json:"notes,omitempty"`
	RecordedBy string    `bson:"recorded_by" json:"recorded_by"`
	RecordedAt time.Time `bson:"recorded_at" json:"recorded_at"`
	CreatedAt  time.Time `bson:"created_at" json:"created_at"`
}

type Medication struct {
	ID        string    `bson:"_id" json:"id"`
	PatientID string    `bson:"patient_id" json:"patient_id"`
	Name      string    `bson:"name" json:"name"`
	Dosage    string    `bson:"dosage" json:"dosage"`
	Schedule  string    `bson:"schedule" json:"schedule"`
	Active    bool      `bson:"active" json:"active"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
}

type MedicationLog struct {
	ID           string    `bson:"_id" json:"id"`
	PatientID    string    `bson:"patient_id" json:"patient_id"`
	MedicationID string    `bson:"medication_id" json:"medication_id"`
	Status       string    `bson:"status" json:"status"`
	TakenAt      time.Time `bson:"taken_at" json:"taken_at"`
	CreatedAt    time.Time `bson:"created_at" json:"created_at"`
}

type Device struct {
	ID           string    `bson:"_id" json:"id"`
	OwnerID      string    `bson:"owner_id" json:"owner_id"`
	SerialNumber string    `bson:"serial_number,omitempty" json:"serial_number,omitempty"`
	Type         string    `bson:"type" json:"type"`
	Status       string    `bson:"status" json:"status"`
	CreatedAt    time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt    time.Time `bson:"updated_at" json:"updated_at"`
}

type DeviceTransferRequest struct {
	ID          string    `bson:"_id" json:"id"`
	DeviceID    string    `bson:"device_id" json:"device_id"`
	FromOwnerID string    `bson:"from_owner_id" json:"from_owner_id"`
	ToOwnerID   string    `bson:"to_owner_id" json:"to_owner_id"`
	Status      string    `bson:"status" json:"status"`
	CreatedAt   time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt   time.Time `bson:"updated_at" json:"updated_at"`
}

type Report struct {
	ID        string    `bson:"_id" json:"id"`
	PatientID string    `bson:"patient_id" json:"patient_id"`
	URL       string    `bson:"url" json:"url"`
	Format    string    `bson:"format" json:"format"`
	CreatedBy string    `bson:"created_by" json:"created_by"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
}

type Notification struct {
	ID        string         `bson:"_id" json:"id"`
	UserID    string         `bson:"user_id" json:"user_id"`
	Channel   string         `bson:"channel" json:"channel"`
	Title     string         `bson:"title" json:"title"`
	Body      string         `bson:"body" json:"body"`
	Metadata  map[string]any `bson:"metadata,omitempty" json:"metadata,omitempty"`
	CreatedAt time.Time      `bson:"created_at" json:"created_at"`
}

type SupportTicket struct {
	ID        string    `bson:"_id" json:"id"`
	UserID    string    `bson:"user_id" json:"user_id"`
	Status    string    `bson:"status" json:"status"`
	Subject   string    `bson:"subject" json:"subject"`
	Body      string    `bson:"body" json:"body"`
	CreatedAt time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time `bson:"updated_at" json:"updated_at"`
}
