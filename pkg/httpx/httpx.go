package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const maxJSONBodyBytes = 1 << 20

type ErrorDetail struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

// ErrorResponse implements RFC 7807 (application/problem+json) while keeping
// the legacy `status`/`message`/`error` fields for backward compatibility
// with existing web and mobile clients.
type ErrorResponse struct {
	Type     string       `json:"type,omitempty"`
	Title    string       `json:"title,omitempty"`
	Status   string       `json:"status"`
	Detail   string       `json:"detail,omitempty"`
	Instance string       `json:"instance,omitempty"`
	Message  string       `json:"message"`
	Error    *ErrorDetail `json:"error,omitempty"`
}

func DecodeJSON(r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxJSONBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("invalid json body")
	}
	return nil
}

func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func WriteError(w http.ResponseWriter, status int, message string) {
	code := strings.ToLower(strings.ReplaceAll(http.StatusText(status), " ", "_"))
	writeProblem(w, status, ErrorResponse{
		Type:    "https://health-apis.onrender.com/v1/openapi.yaml#components/responses/Error",
		Title:   http.StatusText(status),
		Status:  "error",
		Detail:  message,
		Message: message,
		Error: &ErrorDetail{
			Code:    code,
			Message: message,
		},
	})
}

func writeProblem(w http.ResponseWriter, status int, payload ErrorResponse) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func BearerToken(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
}
