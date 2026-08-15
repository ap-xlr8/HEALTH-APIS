package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestPasswordHashAndCheck(t *testing.T) {
	t.Parallel()
	hash, err := HashPassword("Secure!1234")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if !CheckPassword(hash, "Secure!1234") {
		t.Fatal("expected password to match hash")
	}
	if CheckPassword(hash, "Wrong!1234") {
		t.Fatal("expected wrong password to fail")
	}
}

func TestParseRSAKeys(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey returned error: %v", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if _, err := ParseRSAPrivateKey(string(privatePEM)); err != nil {
		t.Fatalf("ParseRSAPrivateKey returned error: %v", err)
	}
	if _, err := ParseRSAPublicKey(string(publicPEM)); err != nil {
		t.Fatalf("ParseRSAPublicKey returned error: %v", err)
	}
}

func TestSignAndVerifyJWT(t *testing.T) {
	t.Parallel()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	token, jti, err := SignJWT(privateKey, "usr_123", "patient", "access", time.Minute)
	if err != nil {
		t.Fatalf("SignJWT returned error: %v", err)
	}
	if jti == "" {
		t.Fatal("expected jwt id")
	}
	claims, err := VerifyJWT(&privateKey.PublicKey, token)
	if err != nil {
		t.Fatalf("VerifyJWT returned error: %v", err)
	}
	if claims.UserID != "usr_123" || claims.Role != "patient" || claims.Kind != "access" || claims.ID != jti {
		t.Fatalf("unexpected claims: %#v", claims)
	}
	if _, err := VerifyJWT(&privateKey.PublicKey, "not-a-token"); err == nil {
		t.Fatal("expected invalid token error")
	}
}
