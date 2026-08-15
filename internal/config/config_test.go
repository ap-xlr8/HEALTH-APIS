package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRequiresSecrets(t *testing.T) {
	t.Setenv("MONGO_URI", "")
	t.Setenv("JWT_PRIVATE_KEY", "")
	t.Setenv("JWT_PUBLIC_KEY", "")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("STRIPE_WEBHOOK_SECRET", "")

	if _, err := Load(); err == nil {
		t.Fatal("expected missing env vars error")
	}
}

func TestLoadParsesRSAKeys(t *testing.T) {
	privatePEM, publicPEM := testKeyPairPEM(t)
	t.Setenv("PORT", "")
	t.Setenv("ENV", "")
	t.Setenv("MONGO_URI", "mongodb://localhost:27017/healthos")
	t.Setenv("JWT_PRIVATE_KEY", escapeLines(privatePEM))
	t.Setenv("JWT_PUBLIC_KEY", escapeLines(publicPEM))
	t.Setenv("STRIPE_SECRET_KEY", "sk_test")
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Port != "8080" || cfg.Env != "dev" || cfg.MongoDatabase != "healthos" {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
	if cfg.JWTPrivateKey == nil || cfg.JWTPublicKey == nil {
		t.Fatal("expected parsed rsa keys")
	}
}

func TestGetEnvAndNormalizePEM(t *testing.T) {
	t.Setenv("HEALTHOS_TEST_ENV", " value ")
	if got := getEnv("HEALTHOS_TEST_ENV", "fallback"); got != "value" {
		t.Fatalf("unexpected env value %q", got)
	}
	_ = os.Unsetenv("HEALTHOS_TEST_ENV")
	if got := getEnv("HEALTHOS_TEST_ENV", "fallback"); got != "fallback" {
		t.Fatalf("unexpected fallback %q", got)
	}
	if got := normalizePEM("a\\nb"); got != "a\nb" {
		t.Fatalf("unexpected normalized pem %q", got)
	}
	if got := stripOptionalQuotes(`"quoted"`); got != "quoted" {
		t.Fatalf("unexpected stripped quotes %q", got)
	}
}

func TestValidateRuntimeConfig(t *testing.T) {
	t.Parallel()
	valid := Config{
		Port:     "8080",
		Env:      "dev",
		MongoURI: "mongodb://localhost:27017/healthos",
	}
	if err := validateRuntimeConfig(valid); err != nil {
		t.Fatalf("expected valid dev config, got %v", err)
	}

	cases := []struct {
		name string
		cfg  Config
	}{
		{name: "bad port", cfg: Config{Port: "http", Env: "dev", MongoURI: "mongodb://localhost:27017/healthos"}},
		{name: "bad env", cfg: Config{Port: "8080", Env: "qa", MongoURI: "mongodb://localhost:27017/healthos"}},
		{name: "staging requires tls", cfg: Config{Port: "8080", Env: "staging", MongoURI: "mongodb://cluster.example.com/healthos"}},
		{name: "prod requires tls", cfg: Config{Port: "8080", Env: "prod", MongoURI: "mongodb://cluster.example.com/healthos"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateRuntimeConfig(tc.cfg); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}

	for _, uri := range []string{
		"mongodb+srv://cluster.example.com/healthos",
		"mongodb://cluster.example.com/healthos?tls=true",
		"mongodb://cluster.example.com/healthos?ssl=true",
	} {
		if err := validateRuntimeConfig(Config{
			Port:                "8080",
			Env:                 "prod",
			MongoURI:            uri,
			StripeSecretKey:     "sk_live_123456",
			StripeWebhookSecret: "whsec_live_123456",
			JWTPrivateKeyPEM:    "real private key material",
			JWTPublicKeyPEM:     "real public key material",
		}); err != nil {
			t.Fatalf("expected tls mongo uri %q to be valid: %v", uri, err)
		}
	}
}

func TestLoadRejectsInsecureProductionMongoURI(t *testing.T) {
	privatePEM, publicPEM := testKeyPairPEM(t)
	t.Setenv("PORT", "8080")
	t.Setenv("ENV", "prod")
	t.Setenv("MONGO_URI", "mongodb://cluster.example.com/healthos")
	t.Setenv("JWT_PRIVATE_KEY", escapeLines(privatePEM))
	t.Setenv("JWT_PUBLIC_KEY", escapeLines(publicPEM))
	t.Setenv("STRIPE_SECRET_KEY", "sk_live")
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_live")

	if _, err := Load(); err == nil {
		t.Fatal("expected insecure prod mongo uri rejection")
	}
}

func TestLoadRejectsPlaceholderSecretsOutsideDev(t *testing.T) {
	privatePEM, publicPEM := testKeyPairPEM(t)
	t.Setenv("PORT", "8080")
	t.Setenv("ENV", "staging")
	t.Setenv("MONGO_URI", "mongodb+srv://cluster.example.com/healthos")
	t.Setenv("JWT_PRIVATE_KEY", escapeLines(privatePEM))
	t.Setenv("JWT_PUBLIC_KEY", escapeLines(publicPEM))
	t.Setenv("STRIPE_SECRET_KEY", "sk_test_replace_me")
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_replace_me")

	if _, err := Load(); err == nil {
		t.Fatal("expected placeholder secret rejection")
	}
}

func TestLoadAllowsPlaceholderSecretsInDev(t *testing.T) {
	privatePEM, publicPEM := testKeyPairPEM(t)
	t.Setenv("PORT", "8080")
	t.Setenv("ENV", "dev")
	t.Setenv("MONGO_URI", "mongodb://localhost:27017/healthos")
	t.Setenv("JWT_PRIVATE_KEY", escapeLines(privatePEM))
	t.Setenv("JWT_PUBLIC_KEY", escapeLines(publicPEM))
	t.Setenv("STRIPE_SECRET_KEY", "sk_test_replace_me")
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_replace_me")

	if _, err := Load(); err != nil {
		t.Fatalf("expected dev placeholder secrets to be allowed, got %v", err)
	}
}

func TestLoadDotEnvFiles(t *testing.T) {
	tempDir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd returned error: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Chdir returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(oldWD)
	})

	t.Setenv("ENV", "already-set")
	if err := os.WriteFile(filepath.Join(tempDir, ".env.local"), []byte("PORT=9090\nENV=from-file\nJWT_PRIVATE_KEY=\"line1\\nline2\"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if err := loadDotEnvFiles(".env.local"); err != nil {
		t.Fatalf("loadDotEnvFiles returned error: %v", err)
	}
	if got := os.Getenv("PORT"); got != "9090" {
		t.Fatalf("expected PORT from file, got %q", got)
	}
	if got := os.Getenv("ENV"); got != "already-set" {
		t.Fatalf("expected existing env to win, got %q", got)
	}
	if got := normalizePEM(os.Getenv("JWT_PRIVATE_KEY")); got != "line1\nline2" {
		t.Fatalf("unexpected escaped pem %q", got)
	}
}

func TestLoadDotEnvFileDoesNotOverrideExplicitEmptyEnv(t *testing.T) {
	tempDir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd returned error: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("Chdir returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(oldWD)
	})

	t.Setenv("PORT", "")
	if err := os.WriteFile(filepath.Join(tempDir, ".env.local"), []byte("PORT=9090\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if err := loadDotEnvFiles(".env.local"); err != nil {
		t.Fatalf("loadDotEnvFiles returned error: %v", err)
	}
	if got := os.Getenv("PORT"); got != "" {
		t.Fatalf("expected explicit empty env to win, got %q", got)
	}
}

func TestLoadDotEnvFileRejectsInvalidLine(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, ".env.local")
	if err := os.WriteFile(path, []byte("not-valid\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if err := loadDotEnvFile(path); err == nil {
		t.Fatal("expected invalid env line error")
	}
}

func testKeyPairPEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	privateBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey returned error: %v", err)
	}
	publicBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}
	return string(pem.EncodeToMemory(privateBlock)), string(pem.EncodeToMemory(publicBlock))
}

func escapeLines(value string) string {
	out := ""
	for _, r := range value {
		if r == '\n' {
			out += `\n`
			continue
		}
		out += string(r)
	}
	return out
}
