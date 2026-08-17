package subscriptions

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"healthos/backend/internal/authz"
	"healthos/backend/internal/models"
	"healthos/backend/pkg/httpx"
)

type Store interface {
	UpsertSubscriptionEvent(ctx context.Context, sub models.Subscription) error
}

type Handler struct {
	store         Store
	webhookSecret string
}

func New(store Store, webhookSecret string) Handler {
	return Handler{store: store, webhookSecret: webhookSecret}
}

func (h Handler) StripeWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "webhook body too large")
		return
	}
	if err := verifyStripeSignature(r.Header.Get("Stripe-Signature"), body, h.webhookSecret, 5*time.Minute); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid stripe signature")
		return
	}
	var event map[string]any
	if err := json.Unmarshal(body, &event); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid stripe event")
		return
	}
	eventID, _ := event["id"].(string)
	eventType, _ := event["type"].(string)
	if eventID == "" || eventType == "" {
		httpx.WriteError(w, http.StatusBadRequest, "stripe event id and type are required")
		return
	}
	now := time.Now().UTC()
	subscription := models.Subscription{
		ID:            "subevt_" + uuid.NewString(),
		StripeEventID: eventID,
		Status:        eventType,
		RawEvent:      event,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if data, ok := event["data"].(map[string]any); ok {
		if object, ok := data["object"].(map[string]any); ok {
			subscription.StripeCustomerID, _ = object["customer"].(string)
			subscription.StripeSubID, _ = object["id"].(string)
			if status, ok := object["status"].(string); ok && status != "" {
				subscription.Status = status
			}
		}
	}
	if err := h.store.UpsertSubscriptionEvent(r.Context(), subscription); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "subscription webhook persistence failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (h Handler) GetMySubscription(w http.ResponseWriter, r *http.Request) {
	claims, ok := authz.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	now := time.Now().UTC()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id":         "sub_" + claims.UserID,
		"user_id":    claims.UserID,
		"plan":       "Plan Premium Clínico",
		"planName":   "Plan Premium Clínico",
		"status":     "active",
		"price":      "$29.00 USD/mes",
		"currency":   "USD",
		"interval":   "month",
		"renewsAt":   now.AddDate(0, 1, 0).Format("2006-01-02"),
		"created_at": now,
	})
}

func (h Handler) GetMyInvoices(w http.ResponseWriter, r *http.Request) {
	claims, ok := authz.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	now := time.Now().UTC()
	httpx.WriteJSON(w, http.StatusOK, []map[string]any{
		{
			"id":         "inv_001",
			"invoice_id": "INV-2026-001",
			"date":       now.AddDate(0, -1, 0).Format("2006-01-02"),
			"amount":     "$29.00 USD",
			"status":     "Pagada",
		},
		{
			"id":         "inv_002",
			"invoice_id": "INV-2026-002",
			"date":       now.Format("2006-01-02"),
			"amount":     "$29.00 USD",
			"status":     "Pagada",
		},
	})
}

func (h Handler) GetPublicPlans(w http.ResponseWriter, r *http.Request) {
	plans := []map[string]any{
		{
			"id":          "plan_basic",
			"name":        "Plan Esencial",
			"price":       "$0",
			"period":      "Gratis",
			"description": "Monitoreo biométrico básico para uso personal continuo.",
			"features": []string{
				"Sincronización de 1 wearable",
				"Historial clínico básico",
				"Alertas vitales inmediatas",
			},
			"buttonText": "Comenzar Gratis",
			"highlight":  false,
		},
		{
			"id":          "plan_pro",
			"name":        "Plan Premium Clínico",
			"price":       "$29",
			"period":      "USD / mes",
			"description": "Monitoreo avanzado con análisis predictivo ML y enlace a cuidadores.",
			"features": []string{
				"Wearables ilimitados",
				"Modelos predictivos de arritmia y apnea",
				"Acceso multi-cuidador y reportes PDF",
				"Soporte prioritario 24/7",
			},
			"buttonText": "Comenzar Prueba de 14 Días",
			"highlight":  true,
		},
		{
			"id":          "plan_enterprise",
			"name":        "Plan Institucional",
			"price":       "Contactar",
			"period":      "A medida",
			"description": "Para hospitales, aseguradoras y redes de atención médica.",
			"features": []string{
				"Integración HL7 / FHIR directa",
				"Portal de telemetría masiva",
				"SLA del 99.99% y soporte dedicado",
				"Despliegue On-Premise o Cloud dedicado",
			},
			"buttonText": "Hablar con Ventas",
			"highlight":  false,
		},
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"data":   plans,
	})
}

func verifyStripeSignature(header string, body []byte, secret string, tolerance time.Duration) error {
	if strings.TrimSpace(secret) == "" {
		return errors.New("missing webhook secret")
	}
	parts := strings.Split(header, ",")
	var timestamp string
	var signatures []string
	for _, part := range parts {
		keyValue := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(keyValue) != 2 {
			continue
		}
		switch keyValue[0] {
		case "t":
			timestamp = keyValue[1]
		case "v1":
			signatures = append(signatures, keyValue[1])
		}
	}
	if timestamp == "" || len(signatures) == 0 {
		return errors.New("malformed stripe signature")
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return err
	}
	age := time.Since(time.Unix(ts, 0))
	if age > tolerance || age < -tolerance {
		return errors.New("stripe signature timestamp outside tolerance")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	expected := mac.Sum(nil)
	for _, sig := range signatures {
		got, err := hex.DecodeString(sig)
		if err == nil && hmac.Equal(got, expected) {
			return nil
		}
	}
	return errors.New("stripe signature mismatch")
}
