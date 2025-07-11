package main

import (
	"log"
	"net/http"

	"github.com/getsentry/sentry-go"
	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"

	"edibubble-api/config"
	"edibubble-api/internal/handlers"
)

func main() {
	cfg := config.Load()

	// Init Sentry
	if err := sentry.Init(sentry.ClientOptions{
		Dsn:              cfg.SentryDSN,
		TracesSampleRate: cfg.SentrySampleRate,
	}); err != nil {
		log.Fatalf("Sentry init failed: %v", err)
	}
	defer sentry.Flush(cfg.SentryFlushTimeout)

	// Init Zap logger
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Define routes
	router := httprouter.New()
	router.GET("/healthcheck", handlers.HealthCheckHandler)

	// Wrap with middleware chain
	handler := utils.buildHandlerStack(cfg, router, logger)

	log.Printf("Server running on port %s [env=%s]", cfg.Port, cfg.Env)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, handler))
}
