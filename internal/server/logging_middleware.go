package server

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"healthos/backend/internal/authz"
)

type responseRecorder struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytesWritten += int64(n)
	return n, err
}

func generateRequestID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "req_" + hex.EncodeToString(b)
}

func LoggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			startTime := time.Now()

			reqID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
			if reqID == "" {
				reqID = generateRequestID()
			}
			w.Header().Set("X-Request-ID", reqID)

			rec := &responseRecorder{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(rec, r)

			latency := time.Since(startTime)

			userID := ""
			role := ""
			if claims, ok := authz.ClaimsFromContext(r.Context()); ok && claims != nil {
				userID = claims.UserID
				role = claims.Role
			}

			remoteIP := r.RemoteAddr
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				parts := strings.Split(xff, ",")
				remoteIP = strings.TrimSpace(parts[0])
			} else if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
				remoteIP = strings.TrimSpace(xrip)
			}

			level := slog.LevelInfo
			if rec.statusCode >= 500 {
				level = slog.LevelError
			} else if rec.statusCode >= 400 {
				level = slog.LevelWarn
			}

			logger.Log(
				r.Context(),
				level,
				"http_request",
				"request_id", reqID,
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.statusCode,
				"latency_ms", latency.Milliseconds(),
				"bytes", rec.bytesWritten,
				"remote_ip", remoteIP,
				"user_id", userID,
				"role", role,
				"user_agent", r.UserAgent(),
			)
		})
	}
}
