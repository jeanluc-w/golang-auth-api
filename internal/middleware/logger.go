package middleware

import (
	"context"
	"net/http"
	"time"

	"edibubble-api/internal/utils"

	"github.com/getsentry/sentry-go"
	"go.uber.org/zap"
)

func LoggerMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get tracking values
			sessionID := utils.GetContextValue(r, "session_id", "")
			requestID := utils.GetContextValue(r, "request_id", "")
			// Start timer and save to context
			start := time.Now()
			ctx := r.Context()
			timedCtx := context.WithValue(ctx, "start_time", start)
			// Log in Zap
			logger.Info("Beginning Request",
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("session_id", sessionID),
				zap.String("request_id", requestID),
				zap.Duration("duration", time.Since(start)),
			)
			// Set panic log for Sentry
			defer func() {
				if err := recover(); err != nil {
					sentry.WithScope(func(scope *sentry.Scope) {
						scope.SetTag("session_id", sessionID)
						scope.SetTag("request_id", requestID)
						scope.SetTag("path", r.URL.Path)
						scope.SetUser(sentry.User{IPAddress: r.RemoteAddr})
						sentry.CurrentHub().Recover(err)
						sentry.Flush(time.Second * 2)
					})
					logger.Error("Internal server error")
					http.Error(w, "Internal server error", http.StatusInternalServerError)
				}
			}()
			// Continue chain with updated context
			next.ServeHTTP(w, r.WithContext(timedCtx))
		})
	}
}
