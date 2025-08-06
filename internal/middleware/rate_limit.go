package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"edibubble-api/config"
	"edibubble-api/internal/entities"
	"edibubble-api/internal/utils"

	"github.com/getsentry/sentry-go"
	"go.uber.org/zap"
)

// Extract user ID from JWT claims stored in context (if set by prior middleware)
func extractRateKey(r *http.Request) string {
	user, _ := r.Context().Value(entities.UserContextKey).(*entities.UserContext)
	if user != nil && user.ID != "" {
		return fmt.Sprintf("user:%s", user.ID)
	}

	ip := strings.Split(r.RemoteAddr, ":")[0]
	return fmt.Sprintf("ip:%s", ip)
}

func RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		key := extractRateKey(r)

		limitCtx, err := config.Loaded.RateLimiter.Get(ctx, key)
		if err != nil {
			utils.LogError(ctx, "Could not get rate limiter in middleware", zap.Error(err))
			utils.JSONError(w, utils.Errors.InternalServerError)
			return
		}

		utils.LogDebug(ctx, "Rate limiting check",
			zap.String("rate_key", key),
			zap.Int64("limit", limitCtx.Limit),
			zap.Int64("remaining", limitCtx.Remaining),
			zap.Int64("reset", limitCtx.Reset),
		)

		// Report when people are exceeding and return an error
		if limitCtx.Reached {
			// Send error to Sentry
			sentry.WithScope(func(scope *sentry.Scope) {
				scope.SetLevel(sentry.LevelWarning)
				scope.SetTag("rate_key", key)
				scope.SetExtra("limit", limitCtx.Limit)
				scope.SetExtra("remaining", limitCtx.Remaining)
				scope.SetExtra("reset", limitCtx.Reset)
			})
			sentry.CaptureMessage("Rate limit exceeded")

			// Log locally and return the JSON error to the client
			utils.LogWarn(ctx, "Rate limit exceeded",
				zap.String("rate_key", key),
				zap.Int64("limit", limitCtx.Limit),
				zap.Int64("remaining", limitCtx.Remaining),
				zap.Int64("reset", limitCtx.Reset),
			)
			utils.JSONError(w, utils.Errors.TooManyAttempts)
			return
		}
		next.ServeHTTP(w, r)
	})
}
