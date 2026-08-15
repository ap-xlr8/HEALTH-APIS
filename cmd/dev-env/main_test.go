package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"healthos/backend/pkg/security"
)

func TestRunWritesParseableLocalEnv(t *testing.T) {
	t.Parallel()
	output := filepath.Join(t.TempDir(), ".env.local")
	if err := run(output, false); err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	contentBytes, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	content := string(contentBytes)
	if !strings.Contains(content, "MONGO_URI=mongodb://localhost:27017/healthos") {
		t.Fatalf("expected local mongo uri in generated env: %s", content)
	}
	privatePEM := extractQuotedValue(t, content, "JWT_PRIVATE_KEY")
	publicPEM := extractQuotedValue(t, content, "JWT_PUBLIC_KEY")
	if _, err := security.ParseRSAPrivateKey(unescapeEnv(privatePEM)); err != nil {
		t.Fatalf("generated private key is not parseable: %v", err)
	}
	if _, err := security.ParseRSAPublicKey(unescapeEnv(publicPEM)); err != nil {
		t.Fatalf("generated public key is not parseable: %v", err)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatalf("Stat returned error: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %v", info.Mode().Perm())
	}
}

func TestRunRejectsExistingFileUnlessForced(t *testing.T) {
	t.Parallel()
	output := filepath.Join(t.TempDir(), ".env.local")
	if err := os.WriteFile(output, []byte("existing"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if err := run(output, false); err == nil {
		t.Fatal("expected existing file rejection")
	}
	if err := run(output, true); err != nil {
		t.Fatalf("expected force overwrite to succeed: %v", err)
	}
}

func TestEscapeEnv(t *testing.T) {
	t.Parallel()
	if got := escapeEnv("a\nb\n"); got != `a\nb` {
		t.Fatalf("unexpected escaped value %q", got)
	}
}

func extractQuotedValue(t *testing.T, content, key string) string {
	t.Helper()
	prefix := key + `="`
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, prefix) && strings.HasSuffix(line, `"`) {
			return strings.TrimSuffix(strings.TrimPrefix(line, prefix), `"`)
		}
	}
	t.Fatalf("missing %s in env", key)
	return ""
}

func unescapeEnv(value string) string {
	return strings.ReplaceAll(value, `\n`, "\n")
}
