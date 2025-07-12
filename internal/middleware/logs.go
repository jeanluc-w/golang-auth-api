package middleware

import (
	"context"
	"net/http"
	"time"

	"edibubble-api/internal/models"
	"edibubble-api/internal/utils"

	"github.com/getsentry/sentry-go"
	"go.uber.org/zap"
)

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

func (rw *responseWriter) Header() http.Header {
	return rw.ResponseWriter.Header()
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	return rw.ResponseWriter.Write(b)
}

func LoggerMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Start timer and save to context
			start := time.Now()

			// Initialize context with start time
			ctx := context.WithValue(r.Context(), models.StartTimeContextKey, start)

			// Extract user context and request ID
			requestID := utils.GetContextString(r, models.RequestContextKey, "")
			userCtx, _ := r.Context().Value(models.UserContextKey).(*models.UserContext)

			reqLogger := logger.With(
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.String("request_id", requestID),
				zap.String("session_id", safe(userCtx, func(u *models.UserContext) string { return u.SessionID })),
				zap.String("user_id", safe(userCtx, func(u *models.UserContext) string { return u.ID })),
				zap.String("remote_addr", r.RemoteAddr),
			)
			ctx = context.WithValue(ctx, models.LoggerContextKey, &utils.DynamicLogger{
				Base:      reqLogger,
				StartTime: start,
			})

			// Update the request with modified context
			r = r.WithContext(ctx)

			// Update Sentry scope pre-request
			sentry.ConfigureScope(func(scope *sentry.Scope) {
				scope.SetTag("request_id", requestID)
				scope.SetTag("path", r.URL.Path)
				scope.SetUser(sentry.User{
					ID:        safe(userCtx, func(u *models.UserContext) string { return u.ID }),
					IPAddress: r.RemoteAddr,
				})
			})

			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

			// Set panic log for Sentry
			defer func() {
				duration := time.Since(start)
				if err := recover(); err != nil {
					sentry.WithScope(func(scope *sentry.Scope) {
						scope.SetTag("request_id", requestID)
						scope.SetTag("path", r.URL.Path)
						scope.SetUser(sentry.User{
							ID:        safe(userCtx, func(u *models.UserContext) string { return u.ID }),
							IPAddress: r.RemoteAddr,
						})
						sentry.CurrentHub().Recover(err)
						sentry.Flush(time.Second * 2)
					})

					reqLogger.Error("Recovered from panic",
						zap.Any("error", err),
						zap.Duration("duration", duration),
					)

					utils.JSONError(rw, http.StatusInternalServerError, "Internal server error")
					return
				}

				reqLogger.With(zap.Duration("duration", duration)).Info("Request Completed",
					zap.Int("status", rw.status),
				)
			}()

			reqLogger.Info("Starting Request")
			next.ServeHTTP(rw, r)
		})
	}
}

// Safe accessor helper
func safe[T any](v *T, get func(*T) string) string {
	if v == nil {
		return ""
	}
	return get(v)
}
