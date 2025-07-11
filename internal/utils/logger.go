package utils

import (
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"
)

func CreateLogger(logger *zap.Logger, r *http.Request) *zap.Logger {
	sessionID := GetContextValue(r, "session_id", "")
	requestID := GetContextValue(r, "request_id", "")
	start := GetContextValue(r, "start_time", "")
	return logger.With(
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("session_id", sessionID),
		zap.String("request_id", requestID),
		zap.Duration("duration", time.Since(start)),
	)
}

// GetLogger retrieves the request-scoped logger from the context.
// Returns a no-op logger if not found, to prevent panics.
func GetLogger(ctx context.Context) *zap.Logger {
	if logger, ok := ctx.Value("logger").(*zap.Logger); ok {
		return logger
	}
	return zap.NewNop() // Fallback to a no-op logger
}
