package config

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/ulule/limiter/v3"
	"github.com/youmark/pkcs8"
)

var Loaded *Config

type Config struct {
	Env                string
	Port               string
	DSN                string
	PasswordPeppersRaw string
	ActivePepperID     string
	SentryDSN          string
	SentrySampleRate   float64
	SentryFlushTimeout time.Duration
	RequestTimeout     time.Duration
	RateLimit          limiter.Rate
	RedisAddress       string
	ResendAPIKey       string
	OTP_TTL            time.Duration
	AccessTTL          time.Duration
	RefreshTTL         time.Duration
	JWTPrivateKey      ed25519.PrivateKey
	JWTPublicKey       ed25519.PublicKey
	JWTAlgorithm       jwt.SigningMethod
}

func Load() *Config {
	_ = godotenv.Load()

	// Establish rate limiter
	rateLimit := limiter.Rate{
		Period: time.Second,
		Limit:  parseIntConfig("REQUEST_RATE_LIMIT", "10"),
	}

	// Return the completed configuration if successful with everything
	Loaded = &Config{
		Env:                getStringConfig("ENV", "development"),
		Port:               getStringConfig("PORT", "8080"),
		DSN:                requireStringConfig("DATABASE_URL"),
		PasswordPeppersRaw: requireStringConfig("PASSWORD_PEPPERS"),
		ActivePepperID:     requireStringConfig("ACTIVE_PEPPER_ID"),
		SentryDSN:          requireStringConfig("SENTRY_DSN"),
		SentrySampleRate:   parseFloatConfig("SENTRY_SAMPLE_RATE", "1"),
		SentryFlushTimeout: 2 * time.Second,
		RedisAddress:       requireStringConfig("REDIS_ADDR"),
		RequestTimeout:     time.Duration(parseIntConfig("REQUEST_TIMEOUT_SECONDS", "10") * int64(time.Second)),
		RateLimit:          rateLimit,
		ResendAPIKey:       requireStringConfig("RESEND_API_KEY"),
		OTP_TTL:            10 * time.Minute,
		AccessTTL:          15 * time.Minute,
		RefreshTTL:         14 * 24 * time.Hour,
		JWTPrivateKey:      loadPrivateKey(requireStringConfig("JWT_PRIVATE_KEY_FILE")),
		JWTPublicKey:       loadPublicKey(requireStringConfig("JWT_PUBLIC_KEY_FILE")),
		JWTAlgorithm:       jwt.SigningMethodEdDSA,
	}
	return nil
}

// Parses a float from env or fallback, fatals if invalid
func parseFloatConfig(key, fallback string) float64 {
	v := getStringConfig(key, fallback)
	i, err := strconv.ParseFloat(v, 64)
	if err != nil {
		log.Fatalf("Failed to parse float from env variable %s: %v", key, err)
	}
	return i
}

// Parses an int from env or fallback, fatals if invalid
func parseIntConfig(key, fallback string) int64 {
	v := getStringConfig(key, fallback)
	i, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		log.Fatalf("Failed to parse int from env variable %s: %v", key, err)
	}
	return i
}

// Gets a string from env or uses fallback
func getStringConfig(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Gets a string from env, fatals if missing
func requireStringConfig(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("Missing env var: %s", key)
	}
	return v
}

func readKeyFile(filename string) (p *pem.Block, rest []byte) {
	keyBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("failed to read private key file: %v", err)
	}
	return pem.Decode(keyBytes)
}

// Load an Ed25519 private key from a PEM file
func loadPrivateKey(filename string) ed25519.PrivateKey {
	block, _ := readKeyFile(filename)
	if block == nil || (block.Type != "PRIVATE KEY" && block.Type != "ENCRYPTED PRIVATE KEY") {
		log.Fatalf("failed to decode PEM block containing the Private key")
	}
	// Parse the private key
	var decryptedKey interface{}
	var err error
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		decryptedKey, err = pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(requireStringConfig("JWT_PRIVATE_KEY_PASSPHRASE")))
	} else {
		decryptedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		log.Fatalf("Failed to parse PKCS8 private key: %v", err)
	}
	if key, ok := decryptedKey.(ed25519.PrivateKey); ok {
		return key
	}
	log.Fatalf("private key is not of type ed25519.PrivateKey")
	return nil
}

// Load an Ed25519 private key from a PEM file
func loadPublicKey(filename string) ed25519.PublicKey {
	block, _ := readKeyFile(filename)
	if block == nil || block.Type != "PUBLIC KEY" {
		log.Fatalf("failed to decode PEM block containing the Public key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse PKIX public key: %v", err)
	}
	// Cast as ed25519.PublicKey
	if key, ok := publicKey.(ed25519.PublicKey); ok {
		return key
	}
	log.Fatalf("private key is not of type ed25519.PublicKey")
	return nil
}

/* TODO: Move to test file
func validateResendAPIKey(client *resend.Client) error {
	dummy := &resend.SendEmailRequest{
		To:      []string{"no-reply@mail.edibubble.com"},
		From:    "Edibubble <no-reply@mail.edibubble.com>",
		Subject: "Test",
		Text:    "This is a test.",
	}

	_, err := client.Emails.Send(dummy)
	if err != nil {
		if strings.Contains(err.Error(), "email address is invalid") {
			// Means the request hit the API and failed for a good reason
			return nil
		}
		return fmt.Errorf("resend validation error: %w", err)
	}
	return nil
}
*/
