package utils

import (
	"context"
	"edibubble-api/internal/entities"
	"fmt"
	"net/http"
	"time"

	"github.com/getsentry/sentry-go"
	"go.uber.org/zap"
)

type DynamicLogger struct {
	Base      *zap.Logger
	StartTime time.Time
}

// Returns a logger with the duration since StartTime
func (l *DynamicLogger) withDuration() *zap.Logger {
	return l.Base.With(zap.Duration("duration", time.Since(l.StartTime)))
}

// Retrieves the request-scoped logger from the context.
// Returns a no-op logger if not found, to prevent panics.
func getLogger(ctx context.Context) *zap.Logger {
	if dynamic, ok := ctx.Value(entities.LoggerContextKey).(*DynamicLogger); ok {
		return dynamic.withDuration()
	}
	return zap.NewNop()
}

// Attaches the duration of the request and then sends a log to Sentry
// with the passed error.
func SendSentryLog(r *http.Request, err error) {
	startTime := GetContextTime(r, entities.StartTimeContextKey)
	sentry.ConfigureScope(func(scope *sentry.Scope) {
		if !startTime.IsZero() {
			scope.SetTag("duration_ms", fmt.Sprintf("%d", time.Since(startTime).Milliseconds()))
		}
	})

	sentry.CaptureException(err)
}

// Simple functions to send logs by level and
// uses the logger created in the logging middleware.
func LogInfo(ctx context.Context, msg string, fields ...zap.Field) {
	logger := getLogger(ctx)
	if logger != nil {
		logger.Info(msg, fields...)
	}
}

func LogWarn(ctx context.Context, msg string, fields ...zap.Field) {
	logger := getLogger(ctx)
	if logger != nil {
		logger.Warn(msg, fields...)
	}
}

func LogError(ctx context.Context, msg string, fields ...zap.Field) {
	logger := getLogger(ctx)
	if logger != nil {
		logger.Error(msg, fields...)
	}
}

func LogDebug(ctx context.Context, msg string, fields ...zap.Field) {
	logger := getLogger(ctx)
	if logger != nil {
		logger.Debug(msg, fields...)
	}
}

func LogPanic(ctx context.Context, msg string, fields ...zap.Field) {
	logger := getLogger(ctx)
	if logger != nil {
		logger.Panic(msg, fields...)
	}
}

func LogFatal(ctx context.Context, msg string, fields ...zap.Field) {
	logger := getLogger(ctx)
	if logger != nil {
		logger.Info(msg, fields...)
	}
}
