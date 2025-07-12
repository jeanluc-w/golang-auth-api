package utils

import (
	"context"
	"edibubble-api/internal/models"
	"time"

	"go.uber.org/zap"
)

type DynamicLogger struct {
	Base      *zap.Logger
	StartTime time.Time
}

// Returns a logger with duration since StartTime
func (l *DynamicLogger) WithDuration() *zap.Logger {
	return l.Base.With(zap.Duration("duration", time.Since(l.StartTime)))
}

// GetLogger retrieves the request-scoped logger from the context.
// Returns a no-op logger if not found, to prevent panics.
func GetLogger(ctx context.Context) *zap.Logger {
	if dynamic, ok := ctx.Value(models.LoggerContextKey).(*DynamicLogger); ok {
		return dynamic.WithDuration()
	}
	return zap.NewNop()
}
