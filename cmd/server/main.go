package main

import (
	"log"
	"net/http"

	"github.com/getsentry/sentry-go"
	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"

	"edibubble-api/config"
	"edibubble-api/internal/handlers"
	"edibubble-api/internal/middleware"
	"edibubble-api/internal/sessions"
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

	// Init session tracker
	sessionTracker := sessions.NewTracker()

	// Define routes
	router := httprouter.New()
	router.GET("/healthcheck", handlers.HealthCheckHandler)

	// Wrap with middleware chain
	handler := middleware.JSONMiddleware(
		middleware.CORSMiddleware(
			middleware.SentryRecoveryMiddleware(
				middleware.LoggerMiddleware(logger)(
					sessions.SessionMiddleware(sessionTracker)(
						router,
					),
				),
			),
		),
	)

	log.Printf("Server running on port %s", cfg.Port)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, handler))
}
