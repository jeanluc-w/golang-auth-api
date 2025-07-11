package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"edibubble-api/config"

	"github.com/ulule/limiter/v3"
	redisstore "github.com/ulule/limiter/v3/drivers/store/redis"
)

// Extract user ID from JWT claims stored in context (if set by prior middleware)
func extractRateKey(r *http.Request) string {
	if userID, ok := r.Context().Value("user_id").(string); ok && userID != "" {
		return fmt.Sprintf("user:%s", userID)
	}
	ip := strings.Split(r.RemoteAddr, ":")[0]
	return fmt.Sprintf("ip:%s", ip)
}

func RateLimitMiddleware(cfg config.Config) func(http.Handler) http.Handler {
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
			key := extractRateKey(r)
			context, err := limiterInstance.Get(r.Context(), key)
			if err != nil {
				http.Error(w, "Rate limiter error", http.StatusInternalServerError)
				return
			}

			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", context.Limit))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", context.Remaining))
			w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", context.Reset))

			if context.Reached {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
