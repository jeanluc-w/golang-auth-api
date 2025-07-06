package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Port               string
	SentryDSN          string
	SentrySampleRate   float64
	SentryFlushTimeout time.Duration
}

func Load() *Config {
	_ = godotenv.Load()

	rate, _ := strconv.ParseFloat(os.Getenv("SENTRY_SAMPLE_RATE"), 64)
	return &Config{
		Port:               get("PORT", "8080"),
		SentryDSN:          must("SENTRY_DSN"),
		SentrySampleRate:   rate,
		SentryFlushTimeout: 2 * time.Second,
	}
}

func get(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func must(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("Missing env var: %s", key)
	}
	return v
}
