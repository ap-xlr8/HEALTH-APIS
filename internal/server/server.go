package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"time"

	"healthos/backend/internal/admin"
	"healthos/backend/internal/alerts"
	"healthos/backend/internal/authz"
	"healthos/backend/internal/breakglass"
	"healthos/backend/internal/clinical"
	"healthos/backend/internal/config"
	"healthos/backend/internal/consent"
	"healthos/backend/internal/devices"
	"healthos/backend/internal/health"
	"healthos/backend/internal/identity"
	"healthos/backend/internal/ml"
	"healthos/backend/internal/models"
	"healthos/backend/internal/notifications"
	"healthos/backend/internal/patients"
	"healthos/backend/internal/realtime"
	"healthos/backend/internal/relationships"
	"healthos/backend/internal/reports"
	"healthos/backend/internal/store"
	"healthos/backend/internal/subscriptions"
	"healthos/backend/internal/support"
	"healthos/backend/pkg/email"
	"healthos/backend/pkg/httpx"
)

type Server struct {
	cfg           config.Config
	logger        *slog.Logger
	store         *store.Mongo
	authz         authz.Middleware
	limiter       *RateLimiter
	admin         admin.Handler
	identity      identity.Handler
	health        health.Handler
	alerts        alerts.Handler
	patients      patients.Handler
	clinical      clinical.Handler
	devices       devices.Handler
	consent       consent.Handler
	relationships relationships.Handler
	reports       reports.Handler
	notifications notifications.Handler
	support       support.Handler
	realtime      *realtime.Hub
	subscriptions subscriptions.Handler
	breakglass    breakglass.Handler
	ml            ml.Handler
	startTime     time.Time
}

func New(cfg config.Config, logger *slog.Logger, mongoStore *store.Mongo) (*Server, error) {
	authzMiddleware := authz.New(cfg.JWTPublicKey, mongoStore)
	hub := realtime.New(logger)
	hub.SetAuthChecker(func(caregiverID, patientID string) bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if active, err := mongoStore.HasActiveRelationship(ctx, caregiverID, patientID); err == nil && active {
			return true
		}
		if hasConsent, err := mongoStore.HasConsentScope(ctx, caregiverID, patientID, models.ScopeReadMeasurements); err == nil && hasConsent {
			return true
		}
		return false
	})
	emailClient := email.NewSendGridClient(cfg.SendGridAPIKey, cfg.SendGridFromEmail, cfg.SendGridFromName)
	return &Server{
		cfg:           cfg,
		logger:        logger,
		store:         mongoStore,
		authz:         authzMiddleware,
		limiter:       NewRateLimiter(),
		admin:         admin.New(mongoStore),
		identity:      identity.New(mongoStore, cfg.JWTPrivateKey, cfg.JWTPublicKey, emailClient),
		health:        health.New(mongoStore, hub),
		alerts:        alerts.New(mongoStore, hub),
		patients:      patients.New(mongoStore),
		clinical:      clinical.New(mongoStore),
		devices:       devices.NewHandler(mongoStore),
		consent:       consent.NewHandler(mongoStore, hub),
		relationships: relationships.NewHandler(mongoStore),
		reports:       reports.New(mongoStore),
		notifications: notifications.New(mongoStore),
		support:       support.New(mongoStore),
		realtime:      hub,
		subscriptions: subscriptions.New(mongoStore, cfg.StripeWebhookSecret),
		breakglass:    breakglass.New(mongoStore),
		ml:            ml.NewHandler(mongoStore),
		startTime:     time.Now().UTC(),
	}, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		if err := s.store.Ping(r.Context()); err != nil {
			httpx.WriteError(w, http.StatusServiceUnavailable, "database connection unhealthy")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"status": "ready",
			"checks": map[string]string{
				"database": "connected",
			},
		})
	})
	mux.Handle("GET /metrics", s.internalToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintf(w, "# HELP go_goroutines Number of goroutines currently running.\n")
		fmt.Fprintf(w, "# TYPE go_goroutines gauge\n")
		fmt.Fprintf(w, "go_goroutines %d\n", runtime.NumGoroutine())
		fmt.Fprintf(w, "# HELP process_uptime_seconds Seconds since the process started.\n")
		fmt.Fprintf(w, "# TYPE process_uptime_seconds gauge\n")
		fmt.Fprintf(w, "process_uptime_seconds %g\n", time.Since(s.startTime).Seconds())
		fmt.Fprintf(w, "# HELP go_memstats_alloc_bytes Number of bytes allocated and still in use.\n")
		fmt.Fprintf(w, "# TYPE go_memstats_alloc_bytes gauge\n")
		fmt.Fprintf(w, "go_memstats_alloc_bytes %d\n", memStats.Alloc)
		fmt.Fprintf(w, "# HELP go_memstats_sys_bytes Number of bytes obtained from the system.\n")
		fmt.Fprintf(w, "# TYPE go_memstats_sys_bytes gauge\n")
		fmt.Fprintf(w, "go_memstats_sys_bytes %d\n", memStats.Sys)
		fmt.Fprintf(w, "# HELP go_memstats_gc_count Number of completed GC cycles.\n")
		fmt.Fprintf(w, "# TYPE go_memstats_gc_count counter\n")
		fmt.Fprintf(w, "go_memstats_gc_count %d\n", memStats.NumGC)
		fmt.Fprintf(w, "# HELP healthos_environment Current runtime environment.\n")
		fmt.Fprintf(w, "# TYPE healthos_environment gauge\n")
		fmt.Fprintf(w, "healthos_environment{env=%q} 1\n", s.cfg.Env)
		globalMetrics.WritePrometheus(w)
	})))
	mux.Handle("GET /v1/openapi.yaml", s.internalToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "api/openapi/openapi.yaml")
	})))
	mux.Handle("GET /v1/asyncapi.yaml", s.internalToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "api/asyncapi/asyncapi.yaml")
	})))

	authLimit := func(h http.Handler) http.Handler {
		return s.limiter.Middleware(100, ipKey, h)
	}
	protected := func(h http.Handler) http.Handler {
		return s.authz.RequireAuth(s.limiter.Middleware(1000, userKey, h))
	}

	mux.Handle("POST /v1/auth/register", authLimit(http.HandlerFunc(s.identity.Register)))
	mux.Handle("POST /v1/auth/verify-email", authLimit(http.HandlerFunc(s.identity.VerifyEmail)))
	mux.Handle("POST /v1/auth/login", authLimit(http.HandlerFunc(s.identity.LoginMobile)))
	mux.Handle("POST /v1/auth/web/login", authLimit(http.HandlerFunc(s.identity.LoginWeb)))
	mux.Handle("POST /v1/auth/2fa/verify", authLimit(http.HandlerFunc(s.identity.Verify2FAMobile)))
	mux.Handle("POST /v1/auth/2fa/web/verify", authLimit(http.HandlerFunc(s.identity.Verify2FAWeb)))
	mux.Handle("POST /v1/auth/2fa/resend", authLimit(http.HandlerFunc(s.identity.Resend2FA)))
	mux.Handle("POST /v1/auth/refresh", authLimit(http.HandlerFunc(s.identity.Refresh)))
	mux.Handle("POST /v1/auth/logout", s.authz.RequireAuth(authLimit(http.HandlerFunc(s.identity.LogoutMobile))))
	mux.Handle("POST /v1/auth/web/logout", s.authz.RequireAuth(authLimit(http.HandlerFunc(s.identity.LogoutWeb))))
	mux.Handle("POST /v1/auth/forgot-password", authLimit(http.HandlerFunc(s.identity.ForgotPassword)))
	mux.Handle("POST /v1/auth/reset-password", authLimit(http.HandlerFunc(s.identity.ResetPassword)))
	mux.Handle("GET /reset-password", http.HandlerFunc(s.identity.ResetPasswordPage))
	mux.Handle("POST /reset-password", authLimit(http.HandlerFunc(s.identity.ResetPasswordPage)))
	mux.Handle("POST /v1/subscriptions/webhook", authLimit(http.HandlerFunc(s.subscriptions.StripeWebhook)))
	mux.Handle("GET /v1/public/plans", authLimit(http.HandlerFunc(s.subscriptions.GetPublicPlans)))

	mux.Handle("GET /v1/admin/users", protected(s.authz.Authorize(
		"users",
		"users:read",
		[]string{models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.admin.ListUsers),
	)))
	mux.Handle("POST /v1/admin/users/{id}/suspend", protected(s.authz.Authorize(
		"users",
		"users:write",
		[]string{models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.admin.SuspendUser),
	)))
	mux.Handle("GET /v1/admin/users/{id}/activity", protected(s.authz.Authorize(
		"users",
		"users:read",
		[]string{models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.admin.GetUserActivity),
	)))
	mux.Handle("GET /v1/admin/audit", protected(s.authz.Authorize(
		"audit_logs",
		"audit:read",
		[]string{models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.admin.ListAuditLogs),
	)))
	mux.Handle("POST /v1/admin/break-glass/request", protected(s.authz.Authorize(
		"break_glass_requests",
		"break_glass:request",
		[]string{models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.breakglass.Request),
	)))
	mux.Handle("POST /v1/admin/break-glass/{id}/approve", protected(s.authz.Authorize(
		"break_glass_requests",
		"break_glass:approve",
		[]string{models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.breakglass.Approve),
	)))

	mux.Handle("POST /v1/sync/measurements", protected(s.authz.Authorize(
		"health_measurements",
		models.ScopeWriteMeasurements,
		[]string{models.RolePatient},
		func(r *http.Request) string {
			if claims, ok := authz.ClaimsFromContext(r.Context()); ok {
				return claims.UserID
			}
			return ""
		},
		http.HandlerFunc(s.health.SyncMeasurements),
	)))
	mux.Handle("POST /v1/sync/critical", protected(s.authz.Authorize(
		"health_measurements",
		models.ScopeWriteMeasurements,
		[]string{models.RolePatient},
		func(r *http.Request) string {
			if claims, ok := authz.ClaimsFromContext(r.Context()); ok {
				return claims.UserID
			}
			return ""
		},
		http.HandlerFunc(s.health.SyncCriticalMeasurements),
	)))
	mux.Handle("GET /v1/patients/{id}/measurements", protected(s.authz.Authorize(
		"health_measurements",
		models.ScopeReadMeasurements,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return r.PathValue("id") },
		http.HandlerFunc(s.health.ListMeasurements),
	)))

	mux.Handle("POST /v1/alerts/sos", protected(s.authz.Authorize(
		"health_alerts",
		models.ScopeWriteMeasurements,
		[]string{models.RolePatient},
		func(r *http.Request) string {
			if claims, ok := authz.ClaimsFromContext(r.Context()); ok {
				return claims.UserID
			}
			return ""
		},
		http.HandlerFunc(s.alerts.TriggerSOS),
	)))

	mux.Handle("GET /v1/alerts", protected(s.authz.Authorize(
		"health_alerts",
		models.ScopeReadAlerts,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string {
			patientID := r.URL.Query().Get("patientId")
			if patientID == "" {
				patientID = r.URL.Query().Get("patient_id")
			}
			return patientID
		},
		http.HandlerFunc(s.alerts.List),
	)))
	mux.Handle("GET /v1/alerts/{id}", protected(s.authz.AuthorizeResolved(
		"health_alerts",
		models.ScopeReadAlerts,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) (string, error) {
			alert, err := s.store.FindAlertByID(r.Context(), r.PathValue("id"))
			return alert.PatientID, err
		},
		http.HandlerFunc(s.alerts.GetAlert),
	)))
	mux.Handle("POST /v1/alerts/{id}/acknowledge", protected(s.authz.AuthorizeResolved(
		"health_alerts",
		models.ScopeReadAlerts,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) (string, error) {
			alert, err := s.store.FindAlertByID(r.Context(), r.PathValue("id"))
			return alert.PatientID, err
		},
		http.HandlerFunc(s.alerts.Acknowledge),
	)))

	mux.Handle("GET /v1/subscriptions/me", protected(s.authz.Authorize(
		"subscriptions",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.subscriptions.GetMySubscription),
	)))
	mux.Handle("GET /v1/subscriptions/me/invoices", protected(s.authz.Authorize(
		"subscriptions",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.subscriptions.GetMyInvoices),
	)))

	mux.Handle("GET /v1/profile/me", protected(s.authz.Authorize(
		"profile",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.identity.Me),
	)))
	mux.Handle("GET /v1/profile/me/preferences", protected(s.authz.Authorize(
		"profile",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.identity.GetPreferences),
	)))
	mux.Handle("PUT /v1/profile/me/preferences", protected(s.authz.Authorize(
		"profile",
		models.ScopeWritePatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.identity.UpdatePreferences),
	)))
	mux.Handle("GET /v1/user/preferences", protected(s.authz.Authorize(
		"profile",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.identity.GetPreferences),
	)))
	mux.Handle("PUT /v1/user/preferences", protected(s.authz.Authorize(
		"profile",
		models.ScopeWritePatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.identity.UpdatePreferences),
	)))
	mux.Handle("PUT /v1/profile/caregiver", protected(s.authz.Authorize(
		"profile",
		models.ScopeWritePatient,
		[]string{models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.identity.UpdateCaregiverProfile),
	)))
	mux.Handle("GET /v1/caregiver/settings", protected(s.authz.Authorize(
		"profile",
		models.ScopeReadPatient,
		[]string{models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.identity.GetCaregiverSettings),
	)))
	mux.Handle("PUT /v1/caregiver/settings", protected(s.authz.Authorize(
		"profile",
		models.ScopeWritePatient,
		[]string{models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.identity.UpdateCaregiverSettings),
	)))
	mux.Handle("GET /v1/patients/{id}/health-profile", protected(s.authz.Authorize(
		"profile",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return r.PathValue("id") },
		http.HandlerFunc(s.patients.GetHealthProfile),
	)))
	mux.Handle("PUT /v1/patients/{id}/health-profile", protected(s.authz.Authorize(
		"profile",
		models.ScopeWritePatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return r.PathValue("id") },
		http.HandlerFunc(s.patients.UpdateHealthProfile),
	)))
	mux.Handle("PUT /v1/patients/me/health-profile", protected(s.authz.Authorize(
		"profile",
		models.ScopeWritePatient,
		[]string{models.RolePatient},
		func(r *http.Request) string {
			if claims, ok := authz.ClaimsFromContext(r.Context()); ok {
				return claims.UserID
			}
			return ""
		},
		http.HandlerFunc(s.patients.UpdateHealthProfile),
	)))
	mux.Handle("GET /v1/patients/{id}", protected(s.authz.Authorize(
		"patients",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return r.PathValue("id") },
		http.HandlerFunc(s.patients.GetPatient),
	)))
	mux.Handle("GET /v1/patients/{id}/risk-assessment", protected(s.authz.Authorize(
		"risk_assessment",
		models.ScopeReadMeasurements,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return r.PathValue("id") },
		http.HandlerFunc(s.ml.GetRiskAssessment),
	)))
	mux.Handle("GET /v1/patients/{id}/biometric-estimations", protected(s.authz.Authorize(
		"biometric_estimations",
		models.ScopeReadMeasurements,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return r.PathValue("id") },
		http.HandlerFunc(s.ml.GetBiometricEstimations),
	)))
	mux.Handle("GET /v1/patients/{id}/ml-estimates", protected(s.authz.Authorize(
		"biometric_estimations",
		models.ScopeReadMeasurements,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return r.PathValue("id") },
		http.HandlerFunc(s.ml.GetBiometricEstimations),
	)))
	mux.Handle("POST /v1/patients/{id}/clinical-records", protected(s.authz.Authorize(
		"clinical_records",
		models.ScopeWriteClinical,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return r.PathValue("id") },
		http.HandlerFunc(s.clinical.CreateClinicalRecord),
	)))
	mux.Handle("GET /v1/patients/{id}/clinical-records", protected(s.authz.Authorize(
		"clinical_records",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return r.PathValue("id") },
		http.HandlerFunc(s.clinical.ListClinicalRecords),
	)))
	mux.Handle("POST /v1/patients/{id}/medications", protected(s.authz.Authorize(
		"medications",
		models.ScopeWriteMedications,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return r.PathValue("id") },
		http.HandlerFunc(s.clinical.CreateMedication),
	)))
	mux.Handle("GET /v1/patients/{id}/medications", protected(s.authz.Authorize(
		"medications",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return r.PathValue("id") },
		http.HandlerFunc(s.clinical.ListMedications),
	)))
	mux.Handle("DELETE /v1/patients/{id}/medications/{med_id}", protected(s.authz.Authorize(
		"medications",
		models.ScopeWriteMedications,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return r.PathValue("id") },
		http.HandlerFunc(s.clinical.DeleteMedication),
	)))
	mux.Handle("POST /v1/patients/{id}/medication-logs", protected(s.authz.Authorize(
		"medication_logs",
		models.ScopeWriteMedications,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return r.PathValue("id") },
		http.HandlerFunc(s.clinical.RecordMedicationLog),
	)))
	mux.Handle("POST /v1/patients/{id}/reports", protected(s.authz.Authorize(
		"reports",
		models.ScopeWriteReports,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return r.PathValue("id") },
		http.HandlerFunc(s.reports.Create),
	)))
	mux.Handle("GET /v1/patients/{id}/reports", protected(s.authz.Authorize(
		"reports",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return r.PathValue("id") },
		http.HandlerFunc(s.reports.List),
	)))
	mux.Handle("GET /v1/patients/{id}/reports/{report_id}/download", protected(s.authz.Authorize(
		"reports",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return r.PathValue("id") },
		http.HandlerFunc(s.reports.Download),
	)))
	mux.Handle("GET /v1/consents", protected(s.authz.Authorize(
		"consents",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.consent.List),
	)))
	mux.Handle("POST /v1/consents", protected(s.authz.Authorize(
		"consents",
		models.ScopeWriteConsent,
		[]string{models.RolePatient},
		func(r *http.Request) string {
			if claims, ok := authz.ClaimsFromContext(r.Context()); ok {
				return claims.UserID
			}
			return ""
		},
		http.HandlerFunc(s.consent.Grant),
	)))
	mux.Handle("DELETE /v1/consents/{caregiver_id}", protected(s.authz.Authorize(
		"consents",
		models.ScopeWriteConsent,
		[]string{models.RolePatient},
		func(r *http.Request) string {
			if claims, ok := authz.ClaimsFromContext(r.Context()); ok {
				return claims.UserID
			}
			return ""
		},
		http.HandlerFunc(s.consent.Revoke),
	)))
	mux.Handle("POST /v1/relationships", protected(s.authz.Authorize(
		"relationships",
		models.ScopeWritePatient,
		[]string{models.RolePatient},
		func(r *http.Request) string {
			if claims, ok := authz.ClaimsFromContext(r.Context()); ok {
				return claims.UserID
			}
			return ""
		},
		http.HandlerFunc(s.relationships.AssignCaregiver),
	)))
	mux.Handle("DELETE /v1/relationships/{caregiver_id}", protected(s.authz.Authorize(
		"relationships",
		models.ScopeWritePatient,
		[]string{models.RolePatient},
		func(r *http.Request) string {
			if claims, ok := authz.ClaimsFromContext(r.Context()); ok {
				return claims.UserID
			}
			return ""
		},
		http.HandlerFunc(s.relationships.RevokeCaregiver),
	)))
	mux.Handle("GET /v1/relationships", protected(s.authz.Authorize(
		"relationships",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.relationships.List),
	)))
	mux.Handle("POST /v1/devices", protected(s.authz.Authorize(
		"devices",
		models.ScopeWriteDevices,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.devices.RegisterWearable),
	)))
	mux.Handle("GET /v1/devices", protected(s.authz.Authorize(
		"devices",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.devices.ListDevices),
	)))
	mux.Handle("GET /v1/patients/{id}/devices", protected(s.authz.Authorize(
		"devices",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return r.PathValue("id") },
		http.HandlerFunc(s.devices.ListDevices),
	)))
	mux.Handle("GET /v1/devices/{id}/sync-config", protected(s.authz.Authorize(
		"devices",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.devices.GetSyncConfig),
	)))
	mux.Handle("POST /v1/devices/{id}/transfer-requests", protected(s.authz.Authorize(
		"device_transfer_requests",
		models.ScopeWriteDevices,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.devices.RequestTransfer),
	)))
	mux.Handle("POST /v1/device-transfer-requests/{id}/approve", protected(s.authz.Authorize(
		"device_transfer_requests",
		models.ScopeWriteDevices,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.devices.ApproveTransfer),
	)))
	mux.Handle("POST /v1/device-transfer-requests/{id}/reject", protected(s.authz.Authorize(
		"device_transfer_requests",
		models.ScopeWriteDevices,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.devices.RejectTransfer),
	)))
	mux.Handle("POST /v1/notifications", protected(s.authz.Authorize(
		"notifications",
		models.ScopeWritePatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.notifications.Create),
	)))
	mux.Handle("GET /v1/notifications", protected(s.authz.Authorize(
		"notifications",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.notifications.List),
	)))
	mux.Handle("GET /v1/notifications/preferences", protected(s.authz.Authorize(
		"notifications",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.notifications.GetPreferences),
	)))
	mux.Handle("PUT /v1/notifications/preferences", protected(s.authz.Authorize(
		"notifications",
		models.ScopeWritePatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.notifications.UpdatePreferences),
	)))
	mux.Handle("POST /v1/support-tickets", protected(s.authz.Authorize(
		"support_tickets",
		models.ScopeWritePatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.support.Create),
	)))
	mux.Handle("GET /v1/support-tickets", protected(s.authz.Authorize(
		"support_tickets",
		models.ScopeReadPatient,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.support.List),
	)))
	mux.Handle("GET /v1/realtime", protected(s.authz.Authorize(
		"realtime",
		models.ScopeReadMeasurements,
		[]string{models.RolePatient, models.RoleCaregiver, models.RoleAdmin},
		func(r *http.Request) string { return "" },
		http.HandlerFunc(s.realtime.Serve),
	)))
	mux.Handle("POST /v1/ml/drift-webhook", s.internalToken(http.HandlerFunc(s.ml.DriftWebhook)))

	return s.secureHeaders(LoggingMiddleware(s.logger)(MetricsMiddleware(mux)))
}

// internalToken protects operational/internal routes (/metrics and API specs).
// In dev (without a configured token) it stays open for local tooling; in any
// other environment it fails closed so an unconfigured token never exposes data.
func (s *Server) internalToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.InternalAPIToken == "" {
			if s.cfg.Env != "dev" {
				httpx.WriteError(w, http.StatusServiceUnavailable, "internal api token is not configured")
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		token := httpx.BearerToken(r)
		if token == "" || token != s.cfg.InternalAPIToken {
			httpx.WriteError(w, http.StatusUnauthorized, "invalid internal api token")
			return
		}
		next.ServeHTTP(w, r)
	})
}
