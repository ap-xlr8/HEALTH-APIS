package realtime

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
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
