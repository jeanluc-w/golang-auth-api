package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/ulule/limiter/v3"
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
	JWTSecret          string
	ResendAPIKey       string
	OTP_TTL            time.Duration
	AccessTTL          time.Duration
	RefreshTTL         time.Duration
}

func Load() *Config {
	_ = godotenv.Load()

	// Establish rate limiter
	rateLimit := limiter.Rate{
		Period: time.Second,
		Limit:  parseIntConfig("REQUEST_RATE_LIMIT", "10"),
	}

	// Establish Resend Client
	resendApiKey := requireStringConfig("RESEND_API_KEY")

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
		JWTSecret:          requireStringConfig("JWT_SECRET"),
		ResendAPIKey:       resendApiKey,
		OTP_TTL:            10 * time.Minute,
		AccessTTL:          15 * time.Minute,
		RefreshTTL:         14 * 24 * time.Hour,
	}
	return nil
}

func parseFloatConfig(key, fallback string) float64 {
	v := getStringConfig(key, fallback)
	i, err := strconv.ParseFloat(v, 64)
	if err != nil {
		log.Fatalf("Failed to parse float from env variable %s: %v", key, err)
	}
	return i
}

func parseIntConfig(key, fallback string) int64 {
	v := getStringConfig(key, fallback)
	i, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		log.Fatalf("Failed to parse int from env variable %s: %v", key, err)
	}
	return i
}

func getStringConfig(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func requireStringConfig(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("Missing env var: %s", key)
	}
	return v
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
