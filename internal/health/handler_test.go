package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"healthos/backend/internal/authz"
	"healthos/backend/internal/models"
	"healthos/backend/pkg/security"
)

type fakeHealthStore struct {
	measurements  []models.Measurement
	alerts        []models.Alert
	notifications []models.Notification
	filter        models.MeasurementFilter
}

func (f *fakeHealthStore) InsertMeasurements(ctx context.Context, measurements []models.Measurement) error {
	f.measurements = measurements
	return nil
}

func (f *fakeHealthStore) ListMeasurements(ctx context.Context, filter models.MeasurementFilter) ([]models.Measurement, error) {
	f.filter = filter
	return f.measurements, nil
}

func (f *fakeHealthStore) CreateAlert(ctx context.Context, alert models.Alert) error {
	f.alerts = append(f.alerts, alert)
	return nil
}

func (f *fakeHealthStore) CreateNotification(ctx context.Context, notification models.Notification) error {
	f.notifications = append(f.notifications, notification)
	return nil
}

type fakeBroadcaster struct {
	events []any
}

func (f *fakeBroadcaster) Broadcast(payload any) {
	f.events = append(f.events, payload)
}

func TestValidateSync(t *testing.T) {
	t.Parallel()
	sq := 0.98
	cd := int64(12)
	req := syncRequest{
		DeviceID: "dev_998877",
		Data: []measurementInput{
			{
				Type:          "heart_rate",
				Value:         75.5,
				Unit:          "bpm",
				Timestamp:     "2023-10-15T14:30:00Z",
				SignalQuality: &sq,
				ClockDriftMs:  &cd,
				SensorSource:  "ppg",
				SessionID:     "sess_1",
			},
			{
				Type:      "blood_oxygen",
				Value:     98,
				Unit:      "%",
				Timestamp: "2023-10-15T14:35:00Z",
			},
			{
				Type:      "steps",
				Value:     1200,
				Unit:      "count",
				Timestamp: "2023-10-15T14:40:00Z",
			},
			{
				Type:      "eda",
				Value:     4.2,
				Unit:      "µS",
				Timestamp: "2023-10-15T14:45:00Z",
			},
			{
				Type:      "skin_temperature",
				Value:     36.6,
				Unit:      "°C",
				Timestamp: "2023-10-15T14:45:00Z",
			},
		},
	}
	measurements, err := validateSync(req, "usr_patient")
	if err != nil {
		t.Fatalf("expected valid sync payload, got %v", err)
	}
	if len(measurements) != 5 || measurements[0].PatientID != "usr_patient" {
		t.Fatalf("unexpected measurements: %#v", measurements)
	}
	if measurements[0].SignalQuality != 0.98 || measurements[0].SensorSource != "ppg" {
		t.Fatalf("unexpected measurement metadata: %#v", measurements[0])
	}

	req.Data[0].Type = "unsupported_type"
	if _, err := validateSync(req, "usr_patient"); err == nil {
		t.Fatal("expected measurement type validation error")
	}
}

func TestDeriveAlert(t *testing.T) {
	t.Parallel()
	req := syncRequest{
		DeviceID: "dev_998877",
		Data: []measurementInput{{
			Type:      "heart_rate",
			Value:     140,
			Unit:      "bpm",
			Timestamp: "2023-10-15T14:30:00Z",
		}},
	}
	measurements, err := validateSync(req, "usr_patient")
	if err != nil {
		t.Fatalf("expected valid sync payload, got %v", err)
	}
	alert, ok := deriveAlert(measurements[0])
	if !ok {
		t.Fatal("expected critical heart-rate alert")
	}
	if alert.Type != "tachycardia" || alert.Severity != "critical" {
		t.Fatalf("unexpected alert: %#v", alert)
	}

	// Bradycardia test
	bradyReq := syncRequest{
		DeviceID: "dev_998877",
		Data: []measurementInput{{
			Type:      "heart_rate",
			Value:     38,
			Unit:      "bpm",
			Timestamp: "2023-10-15T14:30:00Z",
		}},
	}
	bradyMeas, _ := validateSync(bradyReq, "usr_patient")
	bradyAlert, ok := deriveAlert(bradyMeas[0])
	if !ok || bradyAlert.Type != "bradycardia" {
		t.Fatalf("expected bradycardia alert, got %#v", bradyAlert)
	}

	// Fever test
	feverReq := syncRequest{
		DeviceID: "dev_998877",
		Data: []measurementInput{{
			Type:      "skin_temperature",
			Value:     39.5,
			Unit:      "°C",
			Timestamp: "2023-10-15T14:30:00Z",
		}},
	}
	feverMeas, _ := validateSync(feverReq, "usr_patient")
	feverAlert, ok := deriveAlert(feverMeas[0])
	if !ok || feverAlert.Type != "high_fever" {
		t.Fatalf("expected high_fever alert, got %#v", feverAlert)
	}

	// Hypoxemia test
	oxygenReq := syncRequest{
		DeviceID: "dev_998877",
		Data: []measurementInput{{
			Type:      "blood_oxygen",
			Value:     89,
			Unit:      "%",
			Timestamp: "2023-10-15T14:30:00Z",
		}},
	}
	oxygenMeasurements, err := validateSync(oxygenReq, "usr_patient")
	if err != nil {
		t.Fatalf("expected valid oxygen payload, got %v", err)
	}
	oxygenAlert, ok := deriveAlert(oxygenMeasurements[0])
	if !ok || oxygenAlert.Type != "hypoxemia" {
		t.Fatalf("expected hypoxemia alert, got %#v ok=%v", oxygenAlert, ok)
	}

	normal := measurements[0]
	normal.Value = 70
	if alert, ok := deriveAlert(normal); ok {
		t.Fatalf("expected no alert, got %#v", alert)
	}
}

func TestValidateSyncRejectsBadPayloads(t *testing.T) {
	t.Parallel()
	cases := []syncRequest{
		{DeviceID: "", Data: []measurementInput{{Type: "heart_rate", Value: 1, Unit: "bpm", Timestamp: "2023-10-15T14:30:00Z"}}},
		{DeviceID: "dev", Data: nil},
		{DeviceID: "dev", Data: []measurementInput{{Type: "heart_rate", Value: -1, Unit: "bpm", Timestamp: "2023-10-15T14:30:00Z"}}},
		{DeviceID: "dev", Data: []measurementInput{{Type: "heart_rate", Value: 1, Unit: "", Timestamp: "2023-10-15T14:30:00Z"}}},
		{DeviceID: "dev", Data: []measurementInput{{Type: "heart_rate", Value: 1, Unit: "count", Timestamp: "2023-10-15T14:30:00Z"}}},
		{DeviceID: "dev", Data: []measurementInput{{Type: "heart_rate", Value: 1, Unit: "bpm", Timestamp: "not-a-time"}}},
	}
	for _, tc := range cases {
		if _, err := validateSync(tc, "usr_patient"); err == nil {
			t.Fatalf("expected validation error for %#v", tc)
		}
	}
}

func TestSyncMeasurementsHandler(t *testing.T) {
	t.Parallel()
	store := &fakeHealthStore{}
	broadcaster := &fakeBroadcaster{}
	handler := New(store, broadcaster)
	req := httptest.NewRequest(http.MethodPost, "/v1/sync/measurements", strings.NewReader(`{
		"device_id":"dev_998877",
		"data":[{"type":"heart_rate","value":140,"unit":"bpm","timestamp":"2023-10-15T14:30:00Z"}]
	}`))
	req = req.WithContext(authz.WithClaims(req.Context(), &security.Claims{UserID: "usr_patient", Role: models.RolePatient}))
	res := httptest.NewRecorder()

	handler.SyncMeasurements(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", res.Code, res.Body.String())
	}
	if len(store.measurements) != 1 {
		t.Fatalf("expected one stored measurement, got %d", len(store.measurements))
	}
	if len(store.alerts) != 1 {
		t.Fatalf("expected one generated alert, got %d", len(store.alerts))
	}
	if len(store.notifications) != 1 || store.notifications[0].Channel != "push" || store.notifications[0].UserID != "usr_patient" {
		t.Fatalf("expected one push notification for patient, got %#v", store.notifications)
	}
	if len(broadcaster.events) != 3 {
		t.Fatalf("expected measurement, alert, and critical events, got %d", len(broadcaster.events))
	}
}

func TestSyncCriticalMeasurementsHandler(t *testing.T) {
	t.Parallel()
	store := &fakeHealthStore{}
	broadcaster := &fakeBroadcaster{}
	handler := New(store, broadcaster)
	req := httptest.NewRequest(http.MethodPost, "/v1/sync/critical", strings.NewReader(`{
		"device_id":"dev_998877",
		"data":[{"type":"heart_rate","value":160,"unit":"bpm","timestamp":"2023-10-15T14:30:00Z"}]
	}`))
	req = req.WithContext(authz.WithClaims(req.Context(), &security.Claims{UserID: "usr_patient", Role: models.RolePatient}))
	res := httptest.NewRecorder()

	handler.SyncCriticalMeasurements(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", res.Code, res.Body.String())
	}
	if len(store.measurements) != 1 {
		t.Fatalf("expected one stored measurement, got %d", len(store.measurements))
	}
	if len(store.alerts) != 1 {
		t.Fatalf("expected one generated alert, got %d", len(store.alerts))
	}
}

func TestListMeasurementsHandler(t *testing.T) {
	t.Parallel()
	store := &fakeHealthStore{measurements: []models.Measurement{{ID: "meas_1", PatientID: "usr_patient", Type: "heart_rate", Unit: "bpm"}}}
	handler := New(store, nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/patients/usr_patient/measurements?type=heart_rate&limit=50&from=2023-10-15T14:00:00Z&to=2023-10-15T15:00:00Z", nil)
	req.SetPathValue("id", "usr_patient")
	res := httptest.NewRecorder()

	handler.ListMeasurements(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", res.Code, res.Body.String())
	}
	if store.filter.PatientID != "usr_patient" || store.filter.Type != "heart_rate" || store.filter.Limit != 50 {
		t.Fatalf("unexpected filter: %#v", store.filter)
	}
}

func TestListMeasurementsRejectsBadFilters(t *testing.T) {
	t.Parallel()
	handler := New(&fakeHealthStore{}, nil)
	cases := []string{
		"/v1/patients/usr_patient/measurements?limit=0",
		"/v1/patients/usr_patient/measurements?type=invalid_type",
		"/v1/patients/usr_patient/measurements?from=bad-time",
		"/v1/patients/usr_patient/measurements?from=2023-10-16T00:00:00Z&to=2023-10-15T00:00:00Z",
	}
	for _, target := range cases {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.SetPathValue("id", "usr_patient")
		res := httptest.NewRecorder()
		handler.ListMeasurements(res, req)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %s, got %d", target, res.Code)
		}
	}
}

func TestMeasurementFilterDefaultsAndMissingPatient(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/v1/patients/usr_patient/measurements", nil)
	req.SetPathValue("id", "usr_patient")
	filter, err := measurementFilterFromRequest(req)
	if err != nil {
		t.Fatalf("measurementFilterFromRequest returned error: %v", err)
	}
	if filter.PatientID != "usr_patient" || filter.Limit != 100 {
		t.Fatalf("unexpected default filter: %#v", filter)
	}

	if _, err := measurementFilterFromRequest(httptest.NewRequest(http.MethodGet, "/v1/patients//measurements", nil)); err == nil {
		t.Fatal("expected missing patient validation error")
	}
}

func TestBroadcastEventTypesAreDocumentedInAsyncAPI(t *testing.T) {
	t.Parallel()
	store := &fakeHealthStore{}
	broadcaster := &fakeBroadcaster{}
	handler := New(store, broadcaster)
	req := httptest.NewRequest(http.MethodPost, "/v1/sync/measurements", strings.NewReader(`{
		"device_id":"dev_998877",
		"data":[{"type":"heart_rate","value":140,"unit":"bpm","timestamp":"2023-10-15T14:30:00Z"}]
	}`))
	req = req.WithContext(authz.WithClaims(req.Context(), &security.Claims{UserID: "usr_patient", Role: models.RolePatient}))

	handler.SyncMeasurements(httptest.NewRecorder(), req)

	emitted := eventTypesFromPayloads(broadcaster.events)
	documented := documentedAsyncAPIEventTypes(t)
	for _, eventType := range emitted {
		if !documented[eventType] {
			t.Fatalf("emitted realtime event %q is not documented in api/asyncapi/asyncapi.yaml; emitted=%v documented=%v", eventType, emitted, sortedKeys(documented))
		}
	}
}

func TestSyncMeasurementsRejectsCaregiver(t *testing.T) {
	t.Parallel()
	handler := New(&fakeHealthStore{}, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/sync/measurements", strings.NewReader(`{"device_id":"dev","data":[]}`))
	req = req.WithContext(authz.WithClaims(req.Context(), &security.Claims{UserID: "cg_1", Role: models.RoleCaregiver}))
	res := httptest.NewRecorder()

	handler.SyncMeasurements(res, req)

	if res.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", res.Code)
	}
}

func eventTypesFromPayloads(payloads []any) []string {
	seen := map[string]bool{}
	for _, payload := range payloads {
		if event, ok := payload.(map[string]any); ok {
			if eventType, ok := event["type"].(string); ok {
				seen[eventType] = true
			}
		}
	}
	return sortedKeys(seen)
}

func documentedAsyncAPIEventTypes(t *testing.T) map[string]bool {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	source, err := os.ReadFile(filepath.Join(root, "api", "asyncapi", "asyncapi.yaml"))
	if err != nil {
		t.Fatalf("ReadFile asyncapi returned error: %v", err)
	}
	matches := regexp.MustCompile(`const:\s*"?([a-z]+\.[a-z]+(?:\.[a-z]+)?)"?`).FindAllStringSubmatch(string(source), -1)
	documented := map[string]bool{}
	for _, match := range matches {
		documented[match[1]] = true
	}
	return documented
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func TestSyncMeasurementsRejectsMissingClaimsAndBadJSON(t *testing.T) {
	t.Parallel()
	handler := New(&fakeHealthStore{}, nil)
	res := httptest.NewRecorder()
	handler.SyncMeasurements(res, httptest.NewRequest(http.MethodPost, "/v1/sync/measurements", strings.NewReader(`{}`)))
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.Code)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/sync/measurements", strings.NewReader(`{`))
	req = req.WithContext(authz.WithClaims(req.Context(), &security.Claims{UserID: "usr_patient", Role: models.RolePatient}))
	badJSON := httptest.NewRecorder()
	handler.SyncMeasurements(badJSON, req)
	if badJSON.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", badJSON.Code)
	}
}
