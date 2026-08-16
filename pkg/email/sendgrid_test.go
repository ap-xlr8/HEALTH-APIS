package email

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*SendGridClient, <-chan sendGridPayload) {
	t.Helper()
	received := make(chan sendGridPayload, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			t.Errorf("unexpected authorization header %q", r.Header.Get("Authorization"))
		}
		var payload sendGridPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("invalid payload: %v", err)
		}
		received <- payload
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return &SendGridClient{
		apiKey:     "test-api-key",
		fromEmail:  "noreply@healthos.app",
		fromName:   "Health OS",
		httpClient: srv.Client(),
		sendURL:    srv.URL,
	}, received
}

func TestSend2FACode(t *testing.T) {
	t.Parallel()
	client, received := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	ctx := context.Background()
	if err := client.Send2FACode(ctx, "user@example.com", "", "123456", "inicio de sesión"); err != nil {
		t.Fatalf("Send2FACode returned error: %v", err)
	}
	select {
	case payload := <-received:
		if payload.From.Email != "noreply@healthos.app" {
			t.Fatalf("unexpected from %#v", payload.From)
		}
		if got := payload.Personalizations[0].To[0].Email; got != "user@example.com" {
			t.Fatalf("unexpected recipient %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("expected 1 request, got 0")
	}
}

func TestSendVerificationEmail(t *testing.T) {
	t.Parallel()
	client, received := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
	ctx := context.Background()
	if err := client.SendVerificationEmail(ctx, "user@example.com", "Ana", "tok-abc", "987654"); err != nil {
		t.Fatalf("SendVerificationEmail returned error: %v", err)
	}
	select {
	case payload := <-received:
		if payload.Subject != "Verifica tu cuenta en BioGuard Health Platform" {
			t.Fatalf("unexpected subject %q", payload.Subject)
		}
	case <-time.After(time.Second):
		t.Fatal("expected 1 request, got 0")
	}
}

func TestSendPasswordReset(t *testing.T) {
	t.Parallel()
	client, received := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	ctx := context.Background()
	if err := client.SendPasswordReset(ctx, "user@example.com", "Ana", "https://healthos.app/reset?token=abc"); err != nil {
		t.Fatalf("SendPasswordReset returned error: %v", err)
	}
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("expected 1 request, got 0")
	}
}

func TestSendMailNon2xx(t *testing.T) {
	t.Parallel()
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	ctx := context.Background()
	if err := client.Send2FACode(ctx, "user@example.com", "Ana", "123456", "login"); err == nil {
		t.Fatal("expected error on non-2xx response")
	}
}

func TestSendGridShortCircuitsWithoutConfig(t *testing.T) {
	t.Parallel()
	client := &SendGridClient{}
	ctx := context.Background()
	if err := client.Send2FACode(ctx, "user@example.com", "Ana", "123456", "login"); err != nil {
		t.Fatalf("expected no error when unconfigured, got %v", err)
	}
	if err := client.SendVerificationEmail(ctx, "user@example.com", "Ana", "tok", "123456"); err != nil {
		t.Fatalf("expected no error when unconfigured, got %v", err)
	}
	if err := client.SendPasswordReset(ctx, "user@example.com", "Ana", "https://healthos.app"); err != nil {
		t.Fatalf("expected no error when unconfigured, got %v", err)
	}
}
