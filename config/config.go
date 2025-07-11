package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"github.com/ulule/limiter/v3"
)

type Config struct {
	Env                string
	Port               string
	SentryDSN          string
	SentrySampleRate   float64
	SentryFlushTimeout time.Duration
	RequestTimeout     time.Duration
	RateLimit          limiter.Rate
	RedisClient        *redis.Client
}

func Load() *Config {
	_ = godotenv.Load()

	sentry_rate, _ := strconv.ParseFloat(get("SENTRY_SAMPLE_RATE", "1"), 64)
	timeout, _ := strconv.ParseUint(get("REQUEST_TIMEOUT_SECONDS", "10"), 10, 64)
	limit, _ := strconv.ParseInt(get("REQUEST_RATE_LIMIT", "10"), 10, 64)

	ratelimit := limiter.Rate{
		Period: time.Minute,
		Limit:  limit,
	}
	redisClient := redis.NewClient(&redis.Options{
		Addr: get("REDIS_ADDR", "localhost:8030"),
	})
	return &Config{
		Env:                get("ENV", "development"),
		Port:               get("PORT", "8080"),
		SentryDSN:          must("SENTRY_DSN"),
		SentrySampleRate:   sentry_rate,
		SentryFlushTimeout: 2 * time.Second,
		RedisClient:        redisClient,
		RequestTimeout:     time.Duration(timeout * uint64(time.Second)),
		RateLimit:          ratelimit,
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
