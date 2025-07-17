package config

import (
	"context"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"github.com/ulule/limiter/v3"
)

var Loaded *Config

type Config struct {
	Env                string
	Port               string
	PGPool             *pgxpool.Pool
	SentryDSN          string
	SentrySampleRate   float64
	SentryFlushTimeout time.Duration
	RequestTimeout     time.Duration
	RateLimit          limiter.Rate
	RedisClient        *redis.Client
	JWTSecret          string
}

func Load() *Config {
	_ = godotenv.Load()

	// Get variables
	sentry_rate := parseFloatConfig("SENTRY_SAMPLE_RATE", "1")
	timeout := parseIntConfig("REQUEST_TIMEOUT_SECONDS", "10")
	limit := parseIntConfig("REQUEST_RATE_LIMIT", "10")

	// Establish rate limiter
	ratelimit := limiter.Rate{
		Period: time.Minute,
		Limit:  limit,
	}

	// Establish and ping the Redis Client
	redisClient := redis.NewClient(&redis.Options{
		Addr:        requireStringConfig("REDIS_ADDR"),
		DB:          0,
		DialTimeout: 5 * time.Second,
	})
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	// Create pgx pool
	dsn := requireStringConfig("DATABASE_URL")
	pgPool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	// Ping to verify connection
	if err := pgPool.Ping(context.Background()); err != nil {
		log.Fatalf("PostgreSQL ping failed: %v", err)
	}

	// Return the completed configuration if successful with everything
	Loaded = &Config{
		Env:                getStringConfig("ENV", "development"),
		Port:               getStringConfig("PORT", "8080"),
		PGPool:             pgPool,
		SentryDSN:          requireStringConfig("SENTRY_DSN"),
		SentrySampleRate:   sentry_rate,
		SentryFlushTimeout: 2 * time.Second,
		RedisClient:        redisClient,
		RequestTimeout:     time.Duration(timeout * int64(time.Second)),
		RateLimit:          ratelimit,
		JWTSecret:          requireStringConfig("JWT_SECRET"),
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
