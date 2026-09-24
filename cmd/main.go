package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/resend/resend-go/v2"
	"github.com/ulule/limiter/v3"
	redisstore "github.com/ulule/limiter/v3/drivers/store/redis"

	"auth-api/config"
	"auth-api/internal/handlers"
	"auth-api/internal/server"
)

func main() {
	// Load ENV variables
	config.Load()

	// Init Sentry
	config.InitSentry(config.Loaded.SentryDSN, config.Loaded.SentrySampleRate)
	defer sentry.Flush(config.Loaded.SentryFlushTimeout)

	// Init and ping the PostgreSQL connection pool
	pgPool, err := pgxpool.New(context.Background(), config.Loaded.DSN)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	if err := pgPool.Ping(context.Background()); err != nil {
		log.Fatalf("PostgreSQL ping failed: %v", err)
	}

	// Init and ping the Redis Client
	redisClient := redis.NewClient(&redis.Options{
		Addr:        config.Loaded.RedisAddress,
		DB:          0,
		DialTimeout: 5 * time.Second,
	})
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	// Init Resend Email Client
	resendClient := resend.NewClient(config.Loaded.ResendAPIKey)

	// Init Rate Limiter service
	store, err := redisstore.NewStoreWithOptions(redisClient, limiter.StoreOptions{
		Prefix:   "rl",
		MaxRetry: 1,
	})
	if err != nil {
		log.Fatalf("failed to create rate limiter store: %v", err)
	}
	limiterInstance := limiter.New(store, config.Loaded.RateLimit)

	// Init Zap logger
	logger := config.InitLogger(config.Loaded.Env)
	defer logger.Sync()

	// Establish 3rd Party services so handlers/services can use them
	services := server.NewServices(pgPool, redisClient, resendClient, limiterInstance, logger)

	// Build the full application handler: routes + middleware stack
	handler := handlers.NewHandler(services)

	// Create server
	srv := &http.Server{
		Addr:         ":" + config.Loaded.Port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start with graceful shutdown
	server.Start(srv, 15*time.Second)
}
