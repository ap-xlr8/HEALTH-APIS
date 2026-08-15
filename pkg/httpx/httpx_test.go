package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSONRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	var dst struct {
		Email string `json:"email"`
	}
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"email":"a@example.com","extra":true}`))
	if err := DecodeJSON(req, &dst); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestBearerToken(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer token-123")
	if got := BearerToken(req); got != "token-123" {
		t.Fatalf("unexpected bearer token %q", got)
	}
	req.Header.Set("Authorization", "Basic nope")
	if got := BearerToken(req); got != "" {
		t.Fatalf("expected empty bearer token, got %q", got)
	}
}

func TestWriteJSONAndError(t *testing.T) {
	t.Parallel()
	res := httptest.NewRecorder()
	WriteJSON(res, http.StatusCreated, map[string]string{"status": "success"})
	if res.Code != http.StatusCreated || res.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("unexpected json response code=%d content-type=%q", res.Code, res.Header().Get("Content-Type"))
	}
	var payload map[string]string
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json response was invalid: %v", err)
	}

	errRes := httptest.NewRecorder()
	WriteError(errRes, http.StatusBadRequest, "bad")
	if errRes.Code != http.StatusBadRequest {
		t.Fatalf("unexpected error status %d", errRes.Code)
	}
}

func TestDecodeJSONRejectsTrailingValue(t *testing.T) {
	t.Parallel()
	var dst struct {
		Email string `json:"email"`
	}
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"email":"a@example.com"} {"email":"b@example.com"}`))
	if err := DecodeJSON(req, &dst); err == nil {
		t.Fatal("expected trailing json error")
	}
}
