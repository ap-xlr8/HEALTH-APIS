package server

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"healthos/backend/internal/authz"
	"healthos/backend/pkg/httpx"
)

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{buckets: make(map[string]*bucket)}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) Middleware(limitPerMinute int, keyFn func(*http.Request) string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(keyFn(r), float64(limitPerMinute), time.Minute) {
			httpx.WriteError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) allow(key string, capacity float64, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	b := rl.buckets[key]
	if b == nil {
		b = &bucket{tokens: capacity, lastSeen: now}
		rl.buckets[key] = b
	}
	refillRate := capacity / window.Seconds()
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens = min(capacity, b.tokens+elapsed*refillRate)
	b.lastSeen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-10 * time.Minute)
		for key, b := range rl.buckets {
			if b.lastSeen.Before(cutoff) {
				delete(rl.buckets, key)
			}
		}
		rl.mu.Unlock()
	}
}

func ipKey(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 && strings.TrimSpace(parts[0]) != "" {
			return strings.TrimSpace(parts[0])
		}
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func userKey(r *http.Request) string {
	if claims, ok := authz.ClaimsFromContext(r.Context()); ok {
		return claims.UserID
	}
	return ipKey(r)
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token, X-Forwarded-For, Accept, Origin, X-Request-ID")
			w.Header().Set("Access-Control-Expose-Headers", "X-CSRF-Token, Content-Disposition, X-Request-ID")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; object-src 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		w.Header().Set("Cache-Control", "no-store")
		if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") || r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

