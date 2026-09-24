package config

import (
	"log"

	"github.com/getsentry/sentry-go"
)

// InitSentry configures the global Sentry client used for error reporting
// and tracing. It fatals on failure since the rest of the app assumes
// Sentry calls are always safe to make.
func InitSentry(dsn string, sampleRate float64) {
	if err := sentry.Init(sentry.ClientOptions{
		EnableTracing:    true,
		Dsn:              dsn,
		TracesSampleRate: sampleRate,
	}); err != nil {
		log.Fatalf("Sentry init failed: %v", err)
	}
}
