package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"healthos/backend/internal/authz"
	"healthos/backend/pkg/security"
)

func TestRateLimiterAllowsThenRejects(t *testing.T) {
	t.Parallel()
	rl := &RateLimiter{buckets: make(map[string]*bucket)}
	if !rl.allow("ip", 1, time.Hour) {
		t.Fatal("expected first request to pass")
	}
	if rl.allow("ip", 1, time.Hour) {
		t.Fatal("expected second request to be limited")
	}
}

func TestRateLimiterMiddleware(t *testing.T) {
	t.Parallel()
	rl := &RateLimiter{buckets: make(map[string]*bucket)}
	calls := 0
	handler := rl.Middleware(1, func(*http.Request) string { return "client" }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, req)
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, req)

	if first.Code != http.StatusNoContent || second.Code != http.StatusTooManyRequests || calls != 1 {
		t.Fatalf("unexpected rate limit result first=%d second=%d calls=%d", first.Code, second.Code, calls)
	}
}

func TestKeysAndSecureHeaders(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	if got := ipKey(req); got != "192.0.2.10" {
		t.Fatalf("unexpected ip key %q", got)
	}
	req = req.WithContext(authz.WithClaims(req.Context(), &security.Claims{UserID: "usr_1"}))
	if got := userKey(req); got != "usr_1" {
		t.Fatalf("unexpected user key %q", got)
	}

	res := httptest.NewRecorder()
	secureHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(res, req)
	if res.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("expected security headers")
	}
}
