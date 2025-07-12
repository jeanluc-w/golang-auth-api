package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"edibubble-api/config"
	"edibubble-api/internal/models"
	"edibubble-api/internal/utils"

	"github.com/getsentry/sentry-go"
	"github.com/ulule/limiter/v3"
	redisstore "github.com/ulule/limiter/v3/drivers/store/redis"
	"go.uber.org/zap"
)

// Extract user ID from JWT claims stored in context (if set by prior middleware)
func extractRateKey(r *http.Request) string {
	user, _ := r.Context().Value(models.UserContextKey).(*models.UserContext)
	if user != nil && user.ID != "" {
		return fmt.Sprintf("user:%s", user.ID)
	}

	ip := strings.Split(r.RemoteAddr, ":")[0]
	return fmt.Sprintf("ip:%s", ip)
}

func RateLimitMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	store, err := redisstore.NewStoreWithOptions(cfg.RedisClient, limiter.StoreOptions{
		Prefix:   "rl", // namespace prefix
		MaxRetry: 1,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to create redis rate limiter store: %v", err))
	}
	limiterInstance := limiter.New(store, cfg.RateLimit)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger := utils.GetLogger(r.Context())
			key := extractRateKey(r)
			limitCtx, err := limiterInstance.Get(r.Context(), key)
			if err != nil {
				utils.JSONError(w, http.StatusInternalServerError, "Rate limiter error")
				return
			}

			logger.Info("Rate limiting check",
				zap.String("rate_key", key),
				zap.Int64("limit", limitCtx.Limit),
				zap.Int64("remaining", limitCtx.Remaining),
				zap.Int64("reset", limitCtx.Reset),
			)

			// Report when people are exceeding and return an error
			if limitCtx.Reached {
				sentry.WithScope(func(scope *sentry.Scope) {
					scope.SetTag("rate_key", key)
					scope.SetTag("path", r.URL.Path)
					scope.SetTag("method", r.Method)
					scope.SetExtra("limit", limitCtx.Limit)
					scope.SetExtra("remaining", limitCtx.Remaining)
					scope.SetExtra("reset", limitCtx.Reset)
					scope.SetExtra("remote_addr", r.RemoteAddr)
					scope.SetLevel(sentry.LevelWarning)
				})
				sentry.CaptureMessage("Rate limit exceeded")

				// Log locally
				logger.Warn("Rate limit exceeded",
					zap.String("path", r.URL.Path),
					zap.String("method", r.Method),
					zap.String("rate_key", key),
				)

				utils.JSONError(w, http.StatusTooManyRequests, "Rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
