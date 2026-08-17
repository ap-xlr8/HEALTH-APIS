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

type EmergencyContact struct {
	Name         string `bson:"name" json:"name"`
	Phone        string `bson:"phone" json:"phone"`
	Relationship string `bson:"relationship" json:"relationship"`
}

type BaselineVitals struct {
	RestingHeartRate    float64 `bson:"resting_heart_rate,omitempty" json:"resting_heart_rate,omitempty"`
	BaselineSpO2        float64 `bson:"baseline_spo2,omitempty" json:"baseline_spo2,omitempty"`
	BaselineSystolicBP  float64 `bson:"baseline_systolic_bp,omitempty" json:"baseline_systolic_bp,omitempty"`
	BaselineDiastolicBP float64 `bson:"baseline_diastolic_bp,omitempty" json:"baseline_diastolic_bp,omitempty"`
}

type HealthProfile struct {
	WeightKg         float64           `bson:"weight_kg" json:"weight_kg"`
	HeightCm         int               `bson:"height_cm" json:"height_cm"`
	BloodType        string            `bson:"blood_type" json:"blood_type"`
	RhFactor         string            `bson:"rh_factor,omitempty" json:"rh_factor,omitempty"`
	BirthDate        string            `bson:"birth_date,omitempty" json:"birth_date,omitempty"`
	BiologicalSex    string            `bson:"biological_sex,omitempty" json:"biological_sex,omitempty"`
	Gender           string            `bson:"gender,omitempty" json:"gender,omitempty"`
	Phone            string            `bson:"phone,omitempty" json:"phone,omitempty"`
	Address          string            `bson:"address,omitempty" json:"address,omitempty"`
	EmergencyContact *EmergencyContact `bson:"emergency_contact,omitempty" json:"emergency_contact,omitempty"`
	BaselineVitals   *BaselineVitals   `bson:"baseline_vitals,omitempty" json:"baseline_vitals,omitempty"`
	BasalProfile     map[string]any    `bson:"basal_profile,omitempty" json:"basalProfile,omitempty"`
	Allergies        []any             `bson:"allergies,omitempty" json:"allergies,omitempty"`
	Pathological     map[string]any    `bson:"pathological,omitempty" json:"pathological,omitempty"`
	Gynecological    map[string]any    `bson:"gynecological,omitempty" json:"gynecological,omitempty"`
	FamilyHistory    []any             `bson:"family_history,omitempty" json:"familyHistory,omitempty"`
	Lifestyle        map[string]any    `bson:"lifestyle,omitempty" json:"lifestyle,omitempty"`
}

type QuietHours struct {
	Enabled bool   `bson:"enabled" json:"enabled"`
	Start   string `bson:"start" json:"start"`
	End     string `bson:"end" json:"end"`
}

type UserPreferences struct {
	Theme                string     `bson:"theme" json:"theme"`
	Language             string     `bson:"language" json:"language"`
	NotificationChannels []string   `bson:"notification_channels" json:"notification_channels"`
	QuietHours           QuietHours `bson:"quiet_hours" json:"quiet_hours"`
}

type NotificationChannelPreference struct {
	Push  bool `bson:"push" json:"push"`
	Email bool `bson:"email" json:"email"`
	SMS   bool `bson:"sms" json:"sms"`
}

type NotificationPreferences struct {
	Channels   NotificationChannelPreference `bson:"channels" json:"channels"`
	AlertTypes map[string]bool               `bson:"alert_types" json:"alert_types"`
}

type CaregiverProfile struct {
	ProfessionalTitle    string            `bson:"professional_title,omitempty" json:"professional_title,omitempty"`
	LicenseNumber        string            `bson:"license_number,omitempty" json:"license_number,omitempty"`
	Phone                string            `bson:"phone,omitempty" json:"phone,omitempty"`
	Specialty            string            `bson:"specialty,omitempty" json:"specialty,omitempty"`
	Organization         string            `bson:"organization,omitempty" json:"organization,omitempty"`
	Bio                  string            `bson:"bio,omitempty" json:"bio,omitempty"`
	Shifts               map[string]any    `bson:"shifts,omitempty" json:"shifts,omitempty"`
	NotificationChannels map[string]any    `bson:"notification_channels,omitempty" json:"notification_channels,omitempty"`
	EmergencyContact     *EmergencyContact `bson:"emergency_contact,omitempty" json:"emergency_contact,omitempty"`
}

type User struct {
	ID                      string                   `bson:"_id" json:"id"`
	Email                   string                   `bson:"email" json:"email"`
	PasswordHash            string                   `bson:"password_hash" json:"-"`
	Role                    string                   `bson:"role" json:"role"`
	FirstName               string                   `bson:"first_name" json:"first_name"`
	LastName                string                   `bson:"last_name" json:"last_name"`
	Age                     int                      `bson:"age,omitempty" json:"age,omitempty"`
	HealthProfile           *HealthProfile           `bson:"health_profile,omitempty" json:"health_profile,omitempty"`
	CaregiverProfile        *CaregiverProfile        `bson:"caregiver_profile,omitempty" json:"caregiver_profile,omitempty"`
	Preferences             *UserPreferences         `bson:"preferences,omitempty" json:"preferences,omitempty"`
	NotificationPreferences *NotificationPreferences `bson:"notification_preferences,omitempty" json:"notification_preferences,omitempty"`
	ActiveConditions        []string                 `bson:"active_conditions,omitempty" json:"active_conditions,omitempty"`
	Status                  string                   `bson:"status,omitempty" json:"status,omitempty"`
	LastLogin               *time.Time               `bson:"last_login,omitempty" json:"last_login,omitempty"`
	EmailVerified           bool                     `bson:"email_verified" json:"email_verified"`
	VerificationToken       string                   `bson:"verification_token,omitempty" json:"-"`
	VerificationExpiresAt   *time.Time               `bson:"verification_expires_at,omitempty" json:"-"`
	TwoFactorCode           string                   `bson:"two_factor_code,omitempty" json:"-"`
	TwoFactorExpiresAt      *time.Time               `bson:"two_factor_expires_at,omitempty" json:"-"`
	FailedLoginAttempts     int                      `bson:"failed_login_attempts,omitempty" json:"-"`
	LockoutUntil            *time.Time               `bson:"lockout_until,omitempty" json:"-"`
	PasswordResetToken      string                   `bson:"password_reset_token,omitempty" json:"-"`
	PasswordResetExpiresAt  *time.Time               `bson:"password_reset_expires_at,omitempty" json:"-"`
	CreatedAt               time.Time                `bson:"created_at" json:"created_at"`
}

type Session struct {
	ID        string    `bson:"_id"`
	UserID    string    `bson:"user_id"`
	Kind      string    `bson:"kind"`
	ExpiresAt time.Time `bson:"expires_at"`
	CreatedAt time.Time `bson:"created_at"`
}

type Measurement struct {
	ID            string    `bson:"_id" json:"id"`
	PatientID     string    `bson:"patient_id" json:"patient_id"`
	DeviceID      string    `bson:"device_id" json:"device_id"`
	Type          string    `bson:"type" json:"type"`
	Value         float64   `bson:"value" json:"value"`
	Unit          string    `bson:"unit" json:"unit"`
	SignalQuality float64   `bson:"signal_quality,omitempty" json:"signal_quality,omitempty"`
	ClockDriftMs  int64     `bson:"clock_drift_ms,omitempty" json:"clock_drift_ms,omitempty"`
	SensorSource  string    `bson:"sensor_source,omitempty" json:"sensor_source,omitempty"`
	SessionID     string    `bson:"session_id,omitempty" json:"session_id,omitempty"`
	Timestamp     time.Time `bson:"timestamp" json:"timestamp"`
	CreatedAt     time.Time `bson:"created_at" json:"created_at"`
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

type Allergy struct {
	ID                     string   `bson:"id,omitempty" json:"id,omitempty"`
	Allergen               string   `bson:"allergen" json:"allergen"`
	Category               string   `bson:"category,omitempty" json:"category,omitempty"`
	Type                   string   `bson:"type,omitempty" json:"type,omitempty"`
	Severity               string   `bson:"severity" json:"severity"`
	ClinicalManifestations []string `bson:"clinical_manifestations,omitempty" json:"clinical_manifestations,omitempty"`
	ManifestationsText     string   `bson:"manifestations,omitempty" json:"manifestations,omitempty"`
	DiagnosedDate          string   `bson:"diagnosed_date,omitempty" json:"diagnosed_date,omitempty"`
	ReportedDate           string   `bson:"reported_date,omitempty" json:"reported_date,omitempty"`
	Notes                  string   `bson:"notes,omitempty" json:"notes,omitempty"`
}

type PathologicalCondition struct {
	Condition        string   `bson:"condition" json:"condition"`
	ICD10Code        string   `bson:"icd10_code,omitempty" json:"icd10_code,omitempty"`
	OnsetDate        string   `bson:"onset_date,omitempty" json:"onset_date,omitempty"`
	Status           string   `bson:"status,omitempty" json:"status,omitempty"`
	Surgeries        []string `bson:"surgeries,omitempty" json:"surgeries,omitempty"`
	Hospitalizations []string `bson:"hospitalizations,omitempty" json:"hospitalizations,omitempty"`
	Implants         []string `bson:"implants,omitempty" json:"implants,omitempty"`
	Transfusions     []string `bson:"transfusions,omitempty" json:"transfusions,omitempty"`
}

type GynecologicalHistory struct {
	MenarcheAge         int    `bson:"menarche_age,omitempty" json:"menarche_age,omitempty"`
	LastMenstrualPeriod string `bson:"last_menstrual_period,omitempty" json:"last_menstrual_period,omitempty"`
	FormulaGPCA         string `bson:"formula_gpca,omitempty" json:"formula_gpca,omitempty"`
	Contraceptives      string `bson:"contraceptives,omitempty" json:"contraceptives,omitempty"`
	GestationalStatus   string `bson:"gestational_status,omitempty" json:"gestational_status,omitempty"`
}

type FamilyHistoryItem struct {
	Condition    string `bson:"condition" json:"condition"`
	Relationship string `bson:"relationship" json:"relationship"`
	AgeOnset     int    `bson:"age_onset,omitempty" json:"age_onset,omitempty"`
}

type Lifestyle struct {
	SmokingStatus         string  `bson:"smoking_status,omitempty" json:"smoking_status,omitempty"`
	AlcoholFrequency      string  `bson:"alcohol_frequency,omitempty" json:"alcohol_frequency,omitempty"`
	PhysicalActivityLevel string  `bson:"physical_activity_level,omitempty" json:"physical_activity_level,omitempty"`
	SleepQualityScore     float64 `bson:"sleep_quality_score,omitempty" json:"sleep_quality_score,omitempty"`
}

type ClinicalRecord struct {
	ID                   string                  `bson:"_id" json:"id"`
	PatientID            string                  `bson:"patient_id" json:"patient_id"`
	Conditions           []string                `bson:"conditions" json:"conditions"`
	Allergies            []string                `bson:"allergies" json:"allergies"`
	StructuredAllergies  []Allergy               `bson:"structured_allergies,omitempty" json:"structured_allergies,omitempty"`
	PathologyDetails     []PathologicalCondition `bson:"pathology_details,omitempty" json:"pathology_details,omitempty"`
	GynecologicalHistory *GynecologicalHistory   `bson:"gynecological_history,omitempty" json:"gynecological_history,omitempty"`
	FamilyHistory        []FamilyHistoryItem     `bson:"family_history,omitempty" json:"family_history,omitempty"`
	Lifestyle            *Lifestyle              `bson:"lifestyle,omitempty" json:"lifestyle,omitempty"`
	Notes                string                  `bson:"notes,omitempty" json:"notes,omitempty"`
	RecordedBy           string                  `bson:"recorded_by" json:"recorded_by"`
	RecordedAt           time.Time               `bson:"recorded_at" json:"recorded_at"`
	CreatedAt            time.Time               `bson:"created_at" json:"created_at"`
}

type Medication struct {
	ID                     string    `bson:"_id" json:"id"`
	PatientID              string    `bson:"patient_id" json:"patient_id"`
	Name                   string    `bson:"name" json:"name"`
	Dosage                 string    `bson:"dosage" json:"dosage"`
	Schedule               string    `bson:"schedule" json:"schedule"`
	Route                  string    `bson:"route,omitempty" json:"route,omitempty"`
	FrequencyDetails       string    `bson:"frequency_details,omitempty" json:"frequency_details,omitempty"`
	Instructions           string    `bson:"instructions,omitempty" json:"instructions,omitempty"`
	PrescribedBy           string    `bson:"prescribed_by,omitempty" json:"prescribed_by,omitempty"`
	StartDate              string    `bson:"start_date,omitempty" json:"start_date,omitempty"`
	EndDate                string    `bson:"end_date,omitempty" json:"end_date,omitempty"`
	DurationDays           int       `bson:"duration_days,omitempty" json:"duration_days,omitempty"`
	IsIndefinite           bool      `bson:"is_indefinite,omitempty" json:"is_indefinite,omitempty"`
	Status                 string    `bson:"status,omitempty" json:"status,omitempty"`
	ComplementaryTherapies []string  `bson:"complementary_therapies,omitempty" json:"complementary_therapies,omitempty"`
	CalculatedAdherence    float64   `bson:"calculated_adherence,omitempty" json:"calculated_adherence,omitempty"`
	Active                 bool      `bson:"active" json:"active"`
	CreatedAt              time.Time `bson:"created_at" json:"created_at"`
	UpdatedAt              time.Time `bson:"updated_at" json:"updated_at"`
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

type DeviceSyncConfig struct {
	DeviceID           string             `bson:"_id" json:"device_id"`
	SamplingIntervalMs int                `bson:"sampling_interval_ms" json:"sampling_interval_ms"`
	BatchSize          int                `bson:"batch_size" json:"batch_size"`
	CriticalThresholds map[string]float64 `bson:"critical_thresholds" json:"critical_thresholds"`
	UpdatedAt          time.Time          `bson:"updated_at" json:"updated_at"`
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

type MLDriftEvent struct {
	ID                string    `bson:"_id" json:"id"`
	ModelName         string    `bson:"model_name" json:"model_name"`
	Metric            string    `bson:"metric" json:"metric"`
	CurrentDriftScore float64   `bson:"current_drift_score" json:"current_drift_score"`
	Threshold         float64   `bson:"threshold" json:"threshold"`
	Status            string    `bson:"status" json:"status"`
	TriggeredAt       time.Time `bson:"triggered_at" json:"triggered_at"`
	CreatedAt         time.Time `bson:"created_at" json:"created_at"`
}

type BiometricEstimations struct {
	PatientID          string                                 `json:"patient_id"`
	EstimatedGlucose   float64                                `json:"estimated_glucose_mg_dl"`
	StressIndex        float64                                `json:"stress_index"`
	VO2Max             float64                                `json:"vo2_max_ml_kg_min"`
	RecoveryScore      float64                                `json:"recovery_score"`
	Confidence         float64                                `json:"confidence"`
	ClinicalDisclaimer string                                 `json:"clinical_disclaimer"`
	EvaluatedAt        time.Time                              `json:"evaluated_at"`
	Cardiovascular     *CardiovascularRiskEstimate            `json:"cardiovascular,omitempty"`
	Glucose            *GlucoseMetabolicPattern               `json:"glucose,omitempty"`
	StressFatigue      *StressFatigueEstimate                 `json:"stressFatigue,omitempty"`
	SleepApnea         *SleepApneaEstimate                    `json:"sleepApnea,omitempty"`
	Arrhythmias        []ArrhythmiaEvent                      `json:"arrhythmias,omitempty"`
	InfectionAlert     *InfectionDetectionAlert               `json:"infectionAlert,omitempty"`
	ArterialStiffness  *HypertensionArterialStiffnessEstimate `json:"arterialStiffness,omitempty"`
}

type CardiovascularRiskEstimate struct {
	RiskScorePercent     float64 `json:"riskScorePercent"`
	RiskCategory         string  `json:"riskCategory"`
	EstimatedVO2Max      float64 `json:"estimatedVo2Max"`
	AssessmentDate       string  `json:"assessmentDate"`
	ConfidenceScore      float64 `json:"confidenceScore"`
	RegulatoryDisclaimer string  `json:"regulatoryDisclaimer"`
}

type GlucoseMetabolicPattern struct {
	AverageFastingGlucose    float64 `json:"averageFastingGlucose"`
	PostprandialSpikeRisk    string  `json:"postprandialSpikeRisk"`
	GlycemicVariabilityIndex float64 `json:"glycemicVariabilityIndex"`
	Trend                    string  `json:"trend"`
	LastEvaluatedAt          string  `json:"lastEvaluatedAt"`
}

type StressFatigueEstimate struct {
	StressScore             float64 `json:"stressScore"`
	CNSFatigueLevel         string  `json:"cnsFatigueLevel"`
	MorningHrvRmssd         float64 `json:"morningHrvRmssd"`
	SympatheticBalanceRatio float64 `json:"sympatheticBalanceRatio"`
	Recommendation          string  `json:"recommendation"`
}

type SleepApneaEstimate struct {
	OxygenDesaturationIndex  float64 `json:"oxygenDesaturationIndex"`
	NocturnalHypoxemiaEvents int     `json:"nocturnalHypoxemiaEvents"`
	MinNocturnalSpO2         float64 `json:"minNocturnalSpo2"`
	Severity                 string  `json:"severity"`
	MonitoringDate           string  `json:"monitoringDate"`
}

type ArrhythmiaEvent struct {
	ID                     string `json:"id"`
	EventType              string `json:"eventType"`
	EventLabel             string `json:"eventLabel"`
	Timestamp              string `json:"timestamp"`
	DurationSeconds        int    `json:"durationSeconds"`
	PeakHeartRate          int    `json:"peakHeartRate"`
	Severity               string `json:"severity"`
	ClinicalRecommendation string `json:"clinicalRecommendation"`
}

type InfectionDetectionAlert struct {
	IsActive                  bool    `json:"isActive"`
	AlertLevel                string  `json:"alertLevel"`
	BasalTemperatureCelsius   float64 `json:"basalTemperatureCelsius"`
	BasalTemperatureDeviation float64 `json:"basalTemperatureDeviation"`
	RestingHeartRateBpm       int     `json:"restingHeartRateBpm"`
	RestingHeartRateDeviation int     `json:"restingHeartRateDeviation"`
	Message                   string  `json:"message"`
	DetectedAt                string  `json:"detectedAt,omitempty"`
}

type HypertensionArterialStiffnessEstimate struct {
	PulseTransitTimeMs        float64 `json:"pulseTransitTimeMs"`
	ArterialStiffnessCategory string  `json:"arterialStiffnessCategory"`
	HypertensionRiskIndex     float64 `json:"hypertensionRiskIndex"`
	VascularAgeEstimateYears  int     `json:"vascularAgeEstimateYears"`
}
