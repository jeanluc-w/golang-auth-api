package middleware

import (
	"context"
	"edibubble-api/internal/auth"
	"edibubble-api/internal/entities"
	"edibubble-api/internal/server"
	"edibubble-api/internal/utils"
	"net/http"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func isAlternateRoute(path string, routes []string) bool {
	for _, route := range routes {
		if path == route {
			return true
		}
	}
	return false
}

func JWTMiddleware(redisClient *redis.Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			requestPath := r.URL.Path
			// Open Routes: Ignore the routes where they are open to anyone
			if isAlternateRoute(requestPath, server.OpenRoutes) {
				next.ServeHTTP(w, r)
				return
			}

			// If not open, get the token and validate.
			authHeader := r.Header.Get("Authorization")
			utils.LogDebug(ctx, "ROUTES", zap.Any("routes", server.TemporaryJWTRoutes), zap.Any("path", requestPath))

			// TODO: Implement different Auth check if it's the token refresh route since the token should be expired.
			if requestPath == server.V1_RefreshToken {

			}

			// Temporary JWT Routes: Verify the Temporary JWT with different rules if the
			if isAlternateRoute(requestPath, server.TemporaryJWTRoutes) {
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

			// Verify the JWT token like normal and get back the user object if successful
			user, err := auth.VerifyAndParseJWT(ctx, redisClient, authHeader)
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
