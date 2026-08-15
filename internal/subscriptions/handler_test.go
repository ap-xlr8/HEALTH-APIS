package subscriptions

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"healthos/backend/internal/models"
)

func TestVerifyStripeSignature(t *testing.T) {
	t.Parallel()
	secret := "whsec_test"
	body := []byte(`{"id":"evt_123","type":"customer.subscription.updated"}`)
	timestamp := time.Now().Unix()
	payload := []byte(strconv.FormatInt(timestamp, 10) + "." + string(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	header := "t=" + strconv.FormatInt(timestamp, 10) + ",v1=" + hex.EncodeToString(mac.Sum(nil))

	if err := verifyStripeSignature(header, body, secret, 5*time.Minute); err != nil {
		t.Fatalf("expected valid signature, got %v", err)
	}
	if err := verifyStripeSignature(header, []byte(`{"tampered":true}`), secret, 5*time.Minute); err == nil {
		t.Fatal("expected tampered body to fail")
	}
}

type fakeSubscriptionStore struct {
	saved models.Subscription
	err   error
}

func (f *fakeSubscriptionStore) UpsertSubscriptionEvent(ctx context.Context, sub models.Subscription) error {
	if f.err != nil {
		return f.err
	}
	f.saved = sub
	return nil
}

func TestStripeWebhook(t *testing.T) {
	t.Parallel()
	secret := "whsec_test"
	body := `{"id":"evt_123","type":"customer.subscription.updated","data":{"object":{"id":"sub_123","customer":"cus_123","status":"active"}}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/subscriptions/webhook", strings.NewReader(body))
	req.Header.Set("Stripe-Signature", stripeSignatureHeader(secret, []byte(body), time.Now()))
	res := httptest.NewRecorder()
	store := &fakeSubscriptionStore{}

	New(store, secret).StripeWebhook(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", res.Code, res.Body.String())
	}
	if store.saved.StripeEventID != "evt_123" || store.saved.StripeCustomerID != "cus_123" || store.saved.Status != "active" {
		t.Fatalf("unexpected saved subscription: %#v", store.saved)
	}
}

func TestStripeWebhookRejectsBadSignature(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodPost, "/v1/subscriptions/webhook", strings.NewReader(`{"id":"evt_123","type":"x"}`))
	req.Header.Set("Stripe-Signature", "t=123,v1=bad")
	res := httptest.NewRecorder()

	New(&fakeSubscriptionStore{}, "whsec_test").StripeWebhook(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", res.Code)
	}
}

func TestStripeWebhookRejectsMalformedEvent(t *testing.T) {
	t.Parallel()
	body := `{"type":"missing_id"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/subscriptions/webhook", strings.NewReader(body))
	req.Header.Set("Stripe-Signature", stripeSignatureHeader("whsec_test", []byte(body), time.Now()))
	res := httptest.NewRecorder()

	New(&fakeSubscriptionStore{}, "whsec_test").StripeWebhook(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", res.Code)
	}
}

func TestStripeWebhookPersistenceFailure(t *testing.T) {
	t.Parallel()
	body := `{"id":"evt_123","type":"customer.subscription.updated"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/subscriptions/webhook", strings.NewReader(body))
	req.Header.Set("Stripe-Signature", stripeSignatureHeader("whsec_test", []byte(body), time.Now()))
	res := httptest.NewRecorder()

	New(&fakeSubscriptionStore{err: errors.New("db down")}, "whsec_test").StripeWebhook(res, req)

	if res.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", res.Code)
	}
}

func stripeSignatureHeader(secret string, body []byte, ts time.Time) string {
	timestamp := strconv.FormatInt(ts.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "t=" + timestamp + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}
