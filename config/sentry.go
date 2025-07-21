package config

import (
	"log"

	"github.com/getsentry/sentry-go"
)

func InitSentry(dsn string, sampleRate float64) {
	if err := sentry.Init(sentry.ClientOptions{
		EnableTracing:    true,
		Dsn:              dsn,
		TracesSampleRate: sampleRate,
	}); err != nil {
		log.Fatalf("Sentry init failed: %v", err)
	}
}
