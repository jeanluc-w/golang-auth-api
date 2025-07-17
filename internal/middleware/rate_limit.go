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

func RateLimitMiddleware(next http.Handler) http.Handler {
	store, err := redisstore.NewStoreWithOptions(config.Loaded.RedisClient, limiter.StoreOptions{
		Prefix:   "rl", // namespace prefix
		MaxRetry: 1,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to create redis rate limiter store: %v", err))
	}
	limiterInstance := limiter.New(store, config.Loaded.RateLimit)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		key := extractRateKey(r)
		limitCtx, err := limiterInstance.Get(ctx, key)
		if err != nil {
			utils.LogError(ctx, "Could not get rate limiter in middleware", zap.Error(err))
			utils.JSONError(w, http.StatusInternalServerError, "An unkown server error ocurred.")
			return
		}

		utils.LogInfo(ctx, "Rate limiting check", zap.String("rate_key", key))

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

			// Log locally and return an error
			utils.LogWarn(ctx, "Rate limit exceeded", zap.String("rate_key", key))
			utils.JSONError(w, http.StatusTooManyRequests, "Rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}
