// Command cron runs the scheduled database maintenance jobs
// (internal/services.RunMaintenance) once and exits — it's meant to be
// invoked by an external scheduler (system cron, a Kubernetes CronJob, an
// ECS scheduled task, etc.), not run continuously. See the README's
// "Maintenance / cron jobs" section for how to actually schedule it.
//
// It shares config.Load() with the main server (cmd/main.go) rather than
// having its own lighter-weight config loader, so both binaries are built
// from the same image/config in a typical deployment and there's exactly
// one place that knows how to parse the environment. It only actually uses
// DATABASE_URL, but the rest (JWT keys, Resend, etc.) still has to be
// present in its environment as a result.
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"auth-api/config"
	"auth-api/internal/services"
)

func main() {
	config.Load()

	config.InitSentry(config.Loaded.SentryDSN, config.Loaded.SentrySampleRate)
	defer sentry.Flush(config.Loaded.SentryFlushTimeout)

	logger := config.InitLogger(config.Loaded.Env)
	defer logger.Sync()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pgPool, err := pgxpool.New(ctx, config.Loaded.DSN)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	defer pgPool.Close()
	if err := pgPool.Ping(ctx); err != nil {
		log.Fatalf("PostgreSQL ping failed: %v", err)
	}

	start := time.Now()
	if err := services.RunMaintenance(ctx, pgPool); err != nil {
		logger.Error("Maintenance run completed with failures", zap.Error(err), zap.Duration("duration", time.Since(start)))
		sentry.CaptureException(err)
		sentry.Flush(config.Loaded.SentryFlushTimeout)
		os.Exit(1)
	}

	logger.Info("Maintenance run completed successfully", zap.Duration("duration", time.Since(start)))
}
