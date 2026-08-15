package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	output := flag.String("out", ".env.local", "destination env file")
	force := flag.Bool("force", false, "overwrite destination env file")
	flag.Parse()

	if err := run(*output, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(output string, force bool) error {
	if strings.TrimSpace(output) == "" {
		return errors.New("output path is required")
	}
	if _, err := os.Stat(output); err == nil && !force {
		return fmt.Errorf("%s already exists; pass -force to overwrite", output)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	privatePEM, publicPEM, err := rsaKeyPairPEM()
	if err != nil {
		return err
	}
	content := strings.Join([]string{
		"PORT=8080",
		"ENV=dev",
		"MONGO_URI=mongodb://localhost:27017/healthos",
		"MONGO_DATABASE=healthos",
		`JWT_PRIVATE_KEY="` + escapeEnv(privatePEM) + `"`,
		`JWT_PUBLIC_KEY="` + escapeEnv(publicPEM) + `"`,
		"STRIPE_SECRET_KEY=sk_test_local_only",
		"STRIPE_WEBHOOK_SECRET=whsec_local_only",
		"FCM_SERVER_KEY=",
		"",
	}, "\n")
	return os.WriteFile(output, []byte(content), 0o600)
}

func rsaKeyPairPEM() (string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	privateBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	publicBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}
	return string(pem.EncodeToMemory(privateBlock)), string(pem.EncodeToMemory(publicBlock)), nil
}

func escapeEnv(value string) string {
	return strings.ReplaceAll(strings.TrimSpace(value), "\n", `\n`)
}
