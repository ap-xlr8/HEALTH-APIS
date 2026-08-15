package clinical

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

func randomID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

func cleanList(values []string, maxItems, maxLen int) ([]string, bool) {
	if len(values) > maxItems {
		return nil, false
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		clean := strings.TrimSpace(value)
		if clean == "" || len(clean) > maxLen {
			return nil, false
		}
		out = append(out, clean)
	}
	return out, true
}

func allowed(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}
