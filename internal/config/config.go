package config

import (
	"bufio"
	"crypto/rsa"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"healthos/backend/pkg/security"
)

type Config struct {
	Port                string
	Env                 string
	MongoURI            string
	MongoDatabase       string
	JWTPrivateKeyPEM    string
	JWTPublicKeyPEM     string
	JWTPrivateKey       *rsa.PrivateKey
	JWTPublicKey        *rsa.PublicKey
	StripeSecretKey     string
	StripeWebhookSecret string
	FCMServerKey        string
}

func Load() (Config, error) {
	if err := loadDotEnvFiles(".env.local", ".env"); err != nil {
		return Config{}, err
	}

	cfg := Config{
		Port:                getEnv("PORT", "8080"),
		Env:                 getEnv("ENV", "dev"),
		MongoURI:            os.Getenv("MONGO_URI"),
		MongoDatabase:       getEnv("MONGO_DATABASE", "healthos"),
		JWTPrivateKeyPEM:    normalizePEM(os.Getenv("JWT_PRIVATE_KEY")),
		JWTPublicKeyPEM:     normalizePEM(os.Getenv("JWT_PUBLIC_KEY")),
		StripeSecretKey:     os.Getenv("STRIPE_SECRET_KEY"),
		StripeWebhookSecret: os.Getenv("STRIPE_WEBHOOK_SECRET"),
		FCMServerKey:        os.Getenv("FCM_SERVER_KEY"),
	}

	var missing []string
	for key, value := range map[string]string{
		"MONGO_URI":             cfg.MongoURI,
		"JWT_PRIVATE_KEY":       cfg.JWTPrivateKeyPEM,
		"JWT_PUBLIC_KEY":        cfg.JWTPublicKeyPEM,
		"STRIPE_SECRET_KEY":     cfg.StripeSecretKey,
		"STRIPE_WEBHOOK_SECRET": cfg.StripeWebhookSecret,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return Config{}, errors.New("missing required env vars: " + strings.Join(missing, ", "))
	}
	if err := validateRuntimeConfig(cfg); err != nil {
		return Config{}, err
	}

	privateKey, err := security.ParseRSAPrivateKey(cfg.JWTPrivateKeyPEM)
	if err != nil {
		return Config{}, err
	}
	publicKey, err := security.ParseRSAPublicKey(cfg.JWTPublicKeyPEM)
	if err != nil {
		return Config{}, err
	}
	cfg.JWTPrivateKey = privateKey
	cfg.JWTPublicKey = publicKey
	return cfg, nil
}

func validateRuntimeConfig(cfg Config) error {
	if _, err := strconv.Atoi(cfg.Port); err != nil {
		return errors.New("PORT must be numeric")
	}
	switch cfg.Env {
	case "dev", "staging", "prod":
	default:
		return errors.New("ENV must be dev, staging, or prod")
	}
	if cfg.Env != "dev" && !mongoURITLSEnabled(cfg.MongoURI) {
		return errors.New("MONGO_URI must require TLS in staging and prod")
	}
	if cfg.Env != "dev" {
		if looksLikePlaceholderSecret(cfg.StripeSecretKey) || looksLikePlaceholderSecret(cfg.StripeWebhookSecret) {
			return errors.New("staging and prod require non-placeholder Stripe secrets")
		}
		if strings.Contains(cfg.JWTPrivateKeyPEM, "...") || strings.Contains(cfg.JWTPublicKeyPEM, "...") {
			return errors.New("staging and prod require real JWT key material")
		}
	}
	return nil
}

func looksLikePlaceholderSecret(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return true
	}
	for _, marker := range []string{"replace_me", "changeme", "placeholder", "example", "dummy"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func mongoURITLSEnabled(rawURI string) bool {
	if strings.HasPrefix(rawURI, "mongodb+srv://") {
		return true
	}
	parsed, err := url.Parse(rawURI)
	if err != nil {
		return false
	}
	query := parsed.Query()
	return strings.EqualFold(query.Get("tls"), "true") || strings.EqualFold(query.Get("ssl"), "true")
}

func getEnv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func normalizePEM(value string) string {
	return strings.ReplaceAll(stripOptionalQuotes(strings.TrimSpace(value)), `\n`, "\n")
}

func loadDotEnvFiles(paths ...string) error {
	for _, path := range paths {
		if err := loadDotEnvFile(path); err != nil {
			return err
		}
	}
	return nil
}

func loadDotEnvFile(path string) error {
	cleanPath := filepath.Clean(path)
	if cleanPath != filepath.Base(cleanPath) {
		return errors.New("env file path must be a filename in the current directory")
	}
	root, err := os.OpenRoot(".")
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.Open(cleanPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return errors.New("invalid env line in " + path)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return errors.New("empty env key in " + path)
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		if err := os.Setenv(key, stripOptionalQuotes(strings.TrimSpace(value))); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func stripOptionalQuotes(value string) string {
	if len(value) < 2 {
		return value
	}
	if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
		return value[1 : len(value)-1]
	}
	return value
}
