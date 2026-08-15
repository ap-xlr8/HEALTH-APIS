package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestRunReturnsErrorOnMissingConfig(t *testing.T) {
	t.Setenv("MONGO_URI", "")
	t.Setenv("JWT_PRIVATE_KEY", "")
	t.Setenv("JWT_PUBLIC_KEY", "")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("STRIPE_WEBHOOK_SECRET", "")

	if code := run(); code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func TestRunReturnsErrorOnInvalidMongoURI(t *testing.T) {
	privatePEM, publicPEM := mainTestKeyPairPEM(t)
	t.Setenv("MONGO_URI", "://bad-uri")
	t.Setenv("JWT_PRIVATE_KEY", strings.ReplaceAll(privatePEM, "\n", `\n`))
	t.Setenv("JWT_PUBLIC_KEY", strings.ReplaceAll(publicPEM, "\n", `\n`))
	t.Setenv("STRIPE_SECRET_KEY", "sk_test")
	t.Setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")

	if code := run(); code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}

func mainTestKeyPairPEM(t *testing.T) (string, string) {
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
