package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"healthos/backend/internal/authz"
	"healthos/backend/internal/config"
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
	srv := &Server{cfg: config.Config{AllowedOrigins: []string{"http://localhost:5173"}}}
	srv.secureHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(res, req)
	if res.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("expected security headers")
	}
}

func TestIsAllowedOrigin(t *testing.T) {
	t.Parallel()
	srv := &Server{cfg: config.Config{AllowedOrigins: []string{"https://healthos-web.onrender.com", "http://localhost:5173"}}}

	allowed := []string{"https://healthos-web.onrender.com", "http://localhost:5173", "  https://healthos-web.onrender.com  ", "HTTPS://HEALTHOS-WEB.ONRENDER.COM"}
	for _, origin := range allowed {
		if !srv.isAllowedOrigin(origin) {
			t.Fatalf("expected origin %q to be allowed", origin)
		}
	}

	denied := []string{"", "https://evil.example", "https://healthos-web.onrender.com.evil.example", "https://app.healthos.app"}
	for _, origin := range denied {
		if srv.isAllowedOrigin(origin) {
			t.Fatalf("expected origin %q to be denied", origin)
		}
	}
}

func TestSecureHeadersCORSAndOptions(t *testing.T) {
	t.Parallel()
	srv := &Server{cfg: config.Config{AllowedOrigins: []string{"https://healthos-web.onrender.com"}}}
	nextCalled := false
	handler := srv.secureHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	allowed := httptest.NewRequest(http.MethodGet, "/v1/profile/me", nil)
	allowed.Header.Set("Origin", "https://healthos-web.onrender.com")
	allowed.Header.Set("X-Forwarded-Proto", "https")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, allowed)
	if res.Header().Get("Access-Control-Allow-Origin") != "https://healthos-web.onrender.com" {
		t.Fatal("expected CORS allow-origin header")
	}
	if res.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("expected allow-credentials header")
	}
	if res.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("expected HSTS header on https request")
	}
	if !nextCalled {
		t.Fatal("expected next handler to run for GET")
	}

	denied := httptest.NewRequest(http.MethodGet, "/v1/profile/me", nil)
	denied.Header.Set("Origin", "https://evil.example")
	res2 := httptest.NewRecorder()
	nextCalled = false
	handler.ServeHTTP(res2, denied)
	if res2.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("expected no CORS header for denied origin")
	}
	if res2.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("expected no HSTS header on plain http request")
	}

	optionsReq := httptest.NewRequest(http.MethodOptions, "/v1/profile/me", nil)
	optionsReq.Header.Set("Origin", "https://healthos-web.onrender.com")
	res3 := httptest.NewRecorder()
	nextCalled = false
	handler.ServeHTTP(res3, optionsReq)
	if res3.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for OPTIONS preflight, got %d", res3.Code)
	}
	if nextCalled {
		t.Fatal("expected next handler NOT to run for OPTIONS preflight")
	}
}

func TestRateLimiterRefillAndSweep(t *testing.T) {
	rl := &RateLimiter{buckets: make(map[string]*bucket)}
	rl.mu.Lock()
	rl.buckets["stale"] = &bucket{tokens: 1, lastSeen: time.Now().Add(-20 * time.Minute)}
	rl.buckets["fresh"] = &bucket{tokens: 1, lastSeen: time.Now()}
	rl.mu.Unlock()

	rl.sweep(time.Now().Add(-10 * time.Minute))

	rl.mu.Lock()
	_, stale := rl.buckets["stale"]
	_, fresh := rl.buckets["fresh"]
	rl.mu.Unlock()
	if stale {
		t.Fatal("expected stale bucket to be swept")
	}
	if !fresh {
		t.Fatal("expected fresh bucket to be retained")
	}

	if !rl.allow("ip", 2, time.Hour) || !rl.allow("ip", 2, time.Hour) || rl.allow("ip", 2, time.Hour) {
		t.Fatal("expected token refill semantics with capacity 2")
	}
}

func TestIPKeyTrustedHeaders(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		remote  string
		headers map[string]string
		want    string
	}{
		{name: "untrusted xff ignored", remote: "203.0.113.5:80", headers: map[string]string{"X-Forwarded-For": "198.51.100.7"}, want: "203.0.113.5"},
		{name: "trusted xff first hop", remote: "127.0.0.1:80", headers: map[string]string{"X-Forwarded-For": "198.51.100.7, 10.0.0.1"}, want: "198.51.100.7"},
		{name: "trusted xff blank", remote: "10.0.0.9:80", headers: map[string]string{"X-Forwarded-For": " , "}, want: "10.0.0.9"},
		{name: "x real ip", remote: "172.16.0.2:80", headers: map[string]string{"X-Real-IP": "198.51.100.9"}, want: "198.51.100.9"},
		{name: "missing port", remote: "203.0.113.99", want: "203.0.113.99"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remote
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			if got := ipKey(req); got != tc.want {
				t.Fatalf("ipKey = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUserKeyFallsBackToIP(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.55:1234"
	if got := userKey(req); got != "192.0.2.55" {
		t.Fatalf("userKey = %q, want IP fallback", got)
	}
}
