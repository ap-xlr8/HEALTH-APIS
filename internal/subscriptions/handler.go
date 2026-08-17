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
	"os"
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
	httpx.WriteError(w, http.StatusNotFound, "no subscription found for user")
}

func (h Handler) GetMyInvoices(w http.ResponseWriter, r *http.Request) {
	claims, ok := authz.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, []map[string]any{})
}

func (h Handler) GetPublicPlans(w http.ResponseWriter, r *http.Request) {
	var plans []map[string]any
	if raw := strings.TrimSpace(os.Getenv("PUBLIC_PLANS_JSON")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &plans); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "invalid public plans configuration")
			return
		}
	}
	if plans == nil {
		plans = []map[string]any{}
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
