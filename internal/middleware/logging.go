package middleware

import (
	"context"
	"net/http"
	"time"

	"edibubble-api/internal/entities"
	"edibubble-api/internal/utils"

	"github.com/getsentry/sentry-go"
	"go.uber.org/zap"
)

// Safe env accessor helper
func safe[T any](v *T, get func(*T) string) string {
	if v == nil {
		return ""
	}
	return get(v)
}

func LoggerMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Start timer and save to context
			start := time.Now()

			// Initialize context with the request's start time saved
			ctx := context.WithValue(r.Context(), entities.StartTimeContextKey, start)

			// Extract user context and request ID
			requestID := utils.GetContextString(r, entities.RequestContextKey, "")
			userCtx, _ := r.Context().Value(entities.UserContextKey).(*entities.UserContext)

			// Create the dynamic Zap logger with useful fields always attached to any logs.
			reqLogger := logger.With(
				zap.String("path", r.URL.Path),
				zap.String("method", r.Method),
				zap.String("request_id", requestID),
				zap.String("session_id", safe(userCtx, func(u *entities.UserContext) string { return u.SessionID })),
				zap.String("user_id", safe(userCtx, func(u *entities.UserContext) string { return u.ID })),
				zap.String("remote_addr", r.RemoteAddr),
			)
			// Save that logger to the context
			ctx = context.WithValue(ctx, entities.LoggerContextKey, &utils.DynamicLogger{
				Base:      reqLogger,
				StartTime: start,
			})

			// Update Sentry scope pre-request so the tags are always set
			sentry.ConfigureScope(func(scope *sentry.Scope) {
				scope.SetTag("method", r.Method)
				scope.SetTag("path", r.URL.Path)
				scope.SetTag("request_id", requestID)
				scope.SetUser(sentry.User{
					ID:        safe(userCtx, func(u *entities.UserContext) string { return u.ID }),
					IPAddress: r.RemoteAddr,
					Data: map[string]string{
						"session_id": safe(userCtx, func(u *entities.UserContext) string { return u.SessionID }),
					},
				})
				scope.SetTag("user_role", safe(userCtx, func(u *entities.UserContext) string { return u.Role }))
			})

			// Update the request with the logger and start time
			r = r.WithContext(ctx)

			// Set panic loggers for Sentry and Zap.
			defer func() {
				duration := time.Since(start)
				// Log the request to Sentry
				if err := recover(); err != nil {
					sentry.WithScope(func(scope *sentry.Scope) {
						scope.SetTag("request_id", requestID)
						scope.SetTag("path", r.URL.Path)
						scope.SetUser(sentry.User{
							ID:        safe(userCtx, func(u *entities.UserContext) string { return u.ID }),
							IPAddress: r.RemoteAddr,
						})
						sentry.CurrentHub().Recover(err)
						sentry.Flush(time.Second * 2)
					})

					reqLogger.Error("Recovered from panic",
						zap.Any("error", err),
						zap.Duration("duration", duration),
					)

					utils.JSONError(w, http.StatusInternalServerError, utils.Errors.InternalServerError)
					return
				}
				// Log the request completion with duration and HTTP status to Zap
				if rw, ok := w.(*entities.ResponseWriter); ok {
					reqLogger.With(zap.Duration("duration", duration)).Info("Request Completed",
						zap.Int("status", rw.Status),
					)
				} else {
					// Fallback log if something went wrong with custom ResponseWriter
					reqLogger.With(zap.Duration("duration", duration)).Info("Request Completed",
						zap.String("status", "unknown"),
					)
				}
			}()

			reqLogger.Info("Processing Request")
			next.ServeHTTP(w, r)
		})
	}
}
