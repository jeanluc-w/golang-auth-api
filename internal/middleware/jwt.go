package middleware

import (
	"context"
	"edibubble-api/internal/auth"
	"edibubble-api/internal/entities"
	"edibubble-api/internal/server"
	"edibubble-api/internal/utils"
	"net/http"
	"strings"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func isOpenRoute(path string) bool {
	for _, prefix := range server.OpenRoutes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func isTemporaryJWTRoute(path string) bool {
	for _, prefix := range server.TemporaryJWTRoutes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func JWTMiddleware(redisClient *redis.Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Ignore the routes where they are open to anyone
			if isOpenRoute(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			authHeader := r.Header.Get("Authorization")
			ctx := r.Context()

			// Verify the Temporary JWT IF it's the routes we allow them.
			if isTemporaryJWTRoute(r.URL.Path) {
				email, id, err := auth.VerifyTemporaryJWT(ctx, redisClient, authHeader)
				if err != nil {
					utils.LogDebug(ctx, "Temporary JWT validation failed", zap.Error(err))
					utils.JSONError(w, utils.Errors.Unauthorized)
					return
				}
				ctx = context.WithValue(ctx, entities.EmailFromDecodedTempJWTContextKey, email)
				ctx = context.WithValue(ctx, entities.JTIFromDecodedTempJWTContextKey, id)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Verify the JWT token and get back the user object if successful
			user, err := auth.VerifyJWT(ctx, redisClient, authHeader)
			if err != nil {
				utils.LogDebug(ctx, "JWT validation failed", zap.Error(err))
				utils.JSONError(w, utils.Errors.Unauthorized)
				return
			}

			ctx = context.WithValue(ctx, entities.UserContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
