package middleware

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"edibubble-api/internal/entities"
	"edibubble-api/internal/utils"

	"github.com/getsentry/sentry-go"
	"github.com/ulule/limiter/v3"
	"go.uber.org/zap"
)

// Extract user ID from JWT claims stored in context (if set by prior middleware)
func extractRateKey(ctx context.Context, r *http.Request) string {
	if user, _ := ctx.Value(entities.UserContextKey).(*entities.UserContext); user != nil && user.ID != "" {
		return fmt.Sprintf("user:%s", user.ID)
	}
	// safer IP extraction than strings.Split on ":"
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return "ip:" + host
	}
	// fallback (e.g. when RemoteAddr has no port in some envs)
	ip := strings.Split(r.RemoteAddr, ":")[0]
	return "ip:" + ip
}

func RateLimitMiddleware(l *limiter.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// build a rate key (user-id or ip)
			ctx := r.Context()
			key := extractRateKey(ctx, r)

			// limiter.Get returns: ctx, limiter.Context, error
			res, err := l.Get(ctx, key)
			if err != nil {
				utils.LogError(ctx, "Rate limiter store error", zap.Error(err))
				utils.JSONError(w, utils.Errors.InternalServerError)
				return
			}

			utils.LogDebug(ctx, "Rate limiting check",
				zap.String("rate_key", key),
				zap.Int64("limit", res.Limit),
				zap.Int64("remaining", res.Remaining),
				zap.Int64("reset", res.Reset),
			)

			// Report when people are exceeding and return an error
			if res.Reached {
				// Send error to Sentry
				sentry.WithScope(func(scope *sentry.Scope) {
					scope.SetLevel(sentry.LevelWarning)
					scope.SetTag("rate_key", key)
					scope.SetExtra("limit", res.Limit)
					scope.SetExtra("remaining", res.Remaining)
					scope.SetExtra("reset", res.Reset)
				})
				sentry.CaptureMessage("Rate limit exceeded")

				// Log locally and return the JSON error to the client
				utils.LogWarn(ctx, "Rate limit exceeded",
					zap.String("rate_key", key),
					zap.Int64("limit", res.Limit),
					zap.Int64("remaining", res.Remaining),
					zap.Int64("reset", res.Reset),
				)
				utils.JSONError(w, utils.Errors.TooManyAttempts)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
