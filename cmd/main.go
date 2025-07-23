package main

import (
	"net/http"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/julienschmidt/httprouter"

	"edibubble-api/config"
	"edibubble-api/internal/handlers"
	"edibubble-api/internal/server"
)

func main() {
	config.Load()

	// Init Sentry
	config.InitSentry(config.Loaded.SentryDSN, config.Loaded.SentrySampleRate)
	defer sentry.Flush(config.Loaded.SentryFlushTimeout)

	// Init Zap logger
	logger := config.InitLogger(config.Loaded.Env)
	defer logger.Sync()

	// Define API routes
	router := httprouter.New()
	router.GET(server.V1_HealthCheck, handlers.HealthCheckHandler)
	router.POST(server.V1_StartEmailVerification, handlers.StartEmailVerificationHandler)

	// Wrap with middlewares
	handler := handlers.BuildHandlerStack(router, logger)

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
