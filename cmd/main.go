package main

import (
	"log"
	"net/http"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"

	"edibubble-api/config"
	"edibubble-api/internal/handlers"
	"edibubble-api/internal/server"
)

func main() {
	cfg := config.Load()

	// Init Sentry
	if err := sentry.Init(sentry.ClientOptions{
		EnableTracing:    true,
		Dsn:              cfg.SentryDSN,
		TracesSampleRate: cfg.SentrySampleRate,
	}); err != nil {
		log.Fatalf("Sentry init failed: %v", err)
	}
	defer sentry.Flush(cfg.SentryFlushTimeout)

	// Init Zap logger
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize zap logger: %v", err)
	}
	defer logger.Sync()

	// Define routes
	router := httprouter.New()
	router.GET("/healthcheck", handlers.HealthCheckHandler)

	// Wrap with middleware chain
	handler := handlers.BuildHandlerStack(cfg, router, logger)

	// Create server
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start with graceful shutdown
	server.Start(srv, 15*time.Second)
}
