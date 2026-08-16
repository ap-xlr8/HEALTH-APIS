package realtime

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"healthos/backend/internal/authz"
	"healthos/backend/pkg/security"
)

func TestNewBroadcastAndReject(t *testing.T) {
	t.Parallel()
	hub := New(slog.Default())
	if hub == nil {
		t.Fatal("expected hub")
	}
	hub.Broadcast(map[string]string{"type": "measurement.ingested"})

	res := httptest.NewRecorder()
	RejectNonWebSocket(res, httptest.NewRequest(http.MethodGet, "/v1/realtime", nil))
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", res.Code)
	}
}

func TestServeWebSocket(t *testing.T) {
	t.Parallel()
	hub := New(slog.Default())
	server := httptest.NewServer(http.HandlerFunc(hub.Serve))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	waitForClient(t, hub)
	hub.Broadcast(map[string]string{"type": "alert.created"})
	_, message, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage returned error: %v", err)
	}
	if !strings.Contains(string(message), "alert.created") {
		t.Fatalf("unexpected message %s", message)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

func waitForClient(t *testing.T, hub *Hub) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		hub.mu.RLock()
		count := len(hub.clients)
		hub.mu.RUnlock()
		if count > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("websocket client was not registered")
}

func TestSameHostOrigin(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/v1/realtime", nil)
	req.Host = "api.healthos.test"
	if !sameHostOrigin(req) {
		t.Fatal("expected empty origin to be accepted")
	}
	req.Header.Set("Origin", "https://api.healthos.test")
	if !sameHostOrigin(req) {
		t.Fatal("expected same-host origin to be accepted")
	}
	req.Header.Set("Origin", "https://evil.example")
	if sameHostOrigin(req) {
		t.Fatal("expected cross-site origin to be rejected")
	}
	req.Header.Set("Origin", "://bad")
	if sameHostOrigin(req) {
		t.Fatal("expected malformed origin to be rejected")
	}
}

func TestSendToPatientEnforcesPHIIsolation(t *testing.T) {
	hub := New(slog.Default())
	hub.SetAuthChecker(func(caregiverID, patientID string) bool {
		return caregiverID == "cg_1" && patientID == "pat_1"
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if r.Header.Get("X-Test-User") != "" {
			ctx = authz.WithClaims(ctx, &security.Claims{UserID: r.Header.Get("X-Test-User"), Role: r.Header.Get("X-Test-Role")})
		}
		hub.Serve(w, r.WithContext(ctx))
	}))
	defer server.Close()

	dial := func(userID, role string) *websocket.Conn {
		wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
		header := http.Header{}
		if userID != "" {
			header.Set("X-Test-User", userID)
			header.Set("X-Test-Role", role)
		}
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
		if err != nil {
			t.Fatalf("Dial returned error: %v", err)
		}
		return conn
	}

	patient := dial("pat_1", "patient")
	caregiver := dial("cg_1", "caregiver")
	admin := dial("adm_1", "admin")
	anonymous := dial("", "")

	waitForClient(t, hub)
	// Ensure all four are registered before broadcasting
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		hub.mu.RLock()
		count := len(hub.clients)
		hub.mu.RUnlock()
		if count >= 4 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	_ = patient.SetReadDeadline(time.Now().Add(2 * time.Second))
	_ = caregiver.SetReadDeadline(time.Now().Add(2 * time.Second))
	_ = admin.SetReadDeadline(time.Now().Add(2 * time.Second))
	_ = anonymous.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

	hub.SendToPatient("pat_1", map[string]string{"type": "measurement.ingested", "patient_id": "pat_1"})

	assertReceives := func(name string, conn *websocket.Conn) {
		t.Helper()
		_, message, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("%s did not receive targeted PHI: %v", name, err)
		}
		if !strings.Contains(string(message), "measurement.ingested") {
			t.Fatalf("%s received unexpected message %s", name, message)
		}
	}
	assertReceives("patient", patient)
	assertReceives("caregiver", caregiver)
	assertReceives("admin", admin)

	if _, _, err := anonymous.ReadMessage(); err == nil {
		t.Fatal("anonymous client must not receive targeted PHI")
	}

	_ = patient.Close()
	_ = caregiver.Close()
	_ = admin.Close()
	_ = anonymous.Close()
}

func TestSendToPatientExtractsPatientFromPayload(t *testing.T) {
	hub := New(slog.Default())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := authz.WithClaims(r.Context(), &security.Claims{UserID: "pat_2", Role: "patient"})
		hub.Serve(w, r.WithContext(ctx))
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	waitForClient(t, hub)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// patientId (camelCase) fallback field must route PHI to the right patient
	hub.SendToPatient("", map[string]string{"type": "alert.created", "patientId": "pat_2"})

	_, message, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("expected payload-driven delivery: %v", err)
	}
	if !strings.Contains(string(message), "alert.created") {
		t.Fatalf("unexpected message %s", message)
	}
	_ = conn.Close()
}

func TestBroadcastToAllClients(t *testing.T) {
	hub := New(slog.Default())
	server := httptest.NewServer(http.HandlerFunc(hub.Serve))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Dial returned error: %v", err)
	}
	waitForClient(t, hub)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// No patient target -> no PHI isolation applied
	hub.SendToPatient("", map[string]string{"type": "system.operational"})

	_, message, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("expected broadcast delivery: %v", err)
	}
	if !strings.Contains(string(message), "system.operational") {
		t.Fatalf("unexpected message %s", message)
	}
	_ = conn.Close()
}
