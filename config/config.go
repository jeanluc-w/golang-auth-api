package config

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/ulule/limiter/v3"
	"github.com/youmark/pkcs8"
)

var Loaded *Config

type Config struct {
	Env                    string
	Port                   string
	DSN                    string
	PasswordPeppersRaw     string
	ActivePepperID         string
	SentryDSN              string
	SentrySampleRate       float64
	SentryFlushTimeout     time.Duration
	RequestTimeout         time.Duration
	RateLimit              limiter.Rate
	RedisAddress           string
	ResendAPIKey           string
	EmailFromAddress       string
	AllowedOrigins         []string
	OTP_TTL                time.Duration
	AccessTTL              time.Duration
	RefreshTTL             time.Duration
	TemporaryTokenTTL      time.Duration
	LoginMaxFailedAttempts int
	LoginLockDuration      time.Duration
	PasswordResetTTL       time.Duration
	PasswordResetURL       string
	MFAEncryptionKey       []byte
	MFAIssuer              string
	MFAChallengeTTL        time.Duration
	MFARecoveryCodeCount   int
	GoogleClientID         string
	AppleClientID          string
	JWTPrivateKey          ed25519.PrivateKey
	JWTPublicKey           ed25519.PublicKey
	JWTAlgorithm           jwt.SigningMethod
}

// Load reads configuration from the environment (and .env file, if present),
// validates it, and populates the package-level Loaded config. It fatals on
// any missing/invalid required configuration, since the service cannot run
// safely without it.
func Load() {
	_ = godotenv.Load()

	// Establish rate limiter
	rateLimit := limiter.Rate{
		Period: time.Second,
		Limit:  parseIntConfig("REQUEST_RATE_LIMIT", "10"),
	}

	Loaded = &Config{
		Env:                    getStringConfig("ENV", "development"),
		Port:                   getStringConfig("PORT", "8080"),
		DSN:                    requireStringConfig("DATABASE_URL"),
		PasswordPeppersRaw:     requireStringConfig("PASSWORD_PEPPERS"),
		ActivePepperID:         requireStringConfig("ACTIVE_PEPPER_ID"),
		SentryDSN:              requireStringConfig("SENTRY_DSN"),
		SentrySampleRate:       parseFloatConfig("SENTRY_SAMPLE_RATE", "1"),
		SentryFlushTimeout:     2 * time.Second,
		RedisAddress:           requireStringConfig("REDIS_ADDR"),
		RequestTimeout:         time.Duration(parseIntConfig("REQUEST_TIMEOUT_SECONDS", "10") * int64(time.Second)),
		RateLimit:              rateLimit,
		ResendAPIKey:           requireStringConfig("RESEND_API_KEY"),
		EmailFromAddress:       getStringConfig("EMAIL_FROM_ADDRESS", "auth <no-reply@mail.auth.com>"),
		AllowedOrigins:         parseListConfig("ALLOWED_ORIGINS", ""),
		OTP_TTL:                10 * time.Minute,
		AccessTTL:              15 * time.Minute,
		RefreshTTL:             14 * 24 * time.Hour,
		TemporaryTokenTTL:      30 * time.Minute,
		LoginMaxFailedAttempts: int(parseIntConfig("LOGIN_MAX_FAILED_ATTEMPTS", "5")),
		LoginLockDuration:      time.Duration(parseIntConfig("LOGIN_LOCK_DURATION_MINUTES", "15")) * time.Minute,
		PasswordResetTTL:       time.Duration(parseIntConfig("PASSWORD_RESET_TOKEN_TTL_MINUTES", "30")) * time.Minute,
		// Optional: base URL of the frontend's reset-password page (e.g.
		// https://app.example.com/reset-password). If set, the reset email
		// links directly to it with ?token=<raw token> appended; if unset,
		// the email just states the token itself for the client to use
		// however it needs to (deep link, manual entry, etc).
		PasswordResetURL: getStringConfig("PASSWORD_RESET_URL", ""),
		// TOTP secrets are symmetric and must be decrypted (not just
		// hashed) to verify a code, so a DB dump alone must not be enough
		// to read them — same rationale as password peppers, but AES-GCM
		// here since we need the plaintext back, not just a comparison.
		MFAEncryptionKey:     loadMFAEncryptionKey(requireStringConfig("MFA_ENCRYPTION_KEY")),
		MFAIssuer:            getStringConfig("MFA_ISSUER", "auth-api"),
		MFAChallengeTTL:      5 * time.Minute,
		MFARecoveryCodeCount: 10,
		// Optional: unset means that SSO provider's endpoints respond with a
		// clear "not configured" error instead of the service failing to
		// start. Forcing every fork of this repo to have real Google/Apple
		// OAuth credentials just to boot would defeat the point of it being
		// a reference implementation.
		GoogleClientID: getStringConfig("GOOGLE_CLIENT_ID", ""),
		AppleClientID:  getStringConfig("APPLE_CLIENT_ID", ""),
		JWTPrivateKey:  loadPrivateKey(requireStringConfig("JWT_PRIVATE_KEY_FILE")),
		JWTPublicKey:   loadPublicKey(requireStringConfig("JWT_PUBLIC_KEY_FILE")),
		JWTAlgorithm:   jwt.SigningMethodEdDSA,
	}
}

// loadMFAEncryptionKey decodes a base64-encoded 32-byte (256-bit) AES key
// used to encrypt TOTP secrets at rest.
func loadMFAEncryptionKey(raw string) []byte {
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		log.Fatalf("MFA_ENCRYPTION_KEY is not valid base64: %v", err)
	}
	if len(key) != 32 {
		log.Fatalf("MFA_ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256), got %d", len(key))
	}
	return key
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

// Parses a comma-separated list from env or fallback. Empty entries are dropped.
func parseListConfig(key, fallback string) []string {
	raw := getStringConfig(key, fallback)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
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
