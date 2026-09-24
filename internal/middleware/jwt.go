package middleware

import (
	"auth-api/internal/auth"
	"auth-api/internal/entities"
	"auth-api/internal/server"
	"auth-api/internal/utils"
	"context"
	"net/http"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// isAlternateRoute reports whether path is in routes (exact match).
func isAlternateRoute(path string, routes []string) bool {
	for _, route := range routes {
		if path == route {
			return true
		}
	}
	return false
}

// JWTMiddleware authenticates every request except those listed in
// server.OpenRoutes, dispatching to one of three verification modes based
// on the route:
//   - server.V1_RefreshToken: parsed WITHOUT an expiration check, purely to
//     identify the session (see auth.VerifyAndParseExpiredJWT).
//   - server.TemporaryJWTRoutes: verified as a short-lived "joiner" token.
//   - everything else: verified as a normal access token, with the
//     resulting user attached to the request context.
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

			// The refresh-token route is special: the caller's access token
			// is expected to already be expired (or close to it), so it's
			// parsed without an expiration check purely to identify the
			// session. The refresh service still independently authenticates
			// the request via the refresh token itself.
			if requestPath == server.V1_RefreshToken {
				sessionID, userID, err := auth.VerifyAndParseExpiredJWT(ctx, authHeader)
				if err != nil {
					utils.LogDebug(ctx, "Refresh token JWT validation failed", zap.Error(err))
					utils.JSONError(w, utils.Errors.Unauthorized)
					return
				}
				ctx = context.WithValue(ctx, entities.SessionIDFromExpiredJWTContextKey, sessionID)
				ctx = context.WithValue(ctx, entities.UserIDFromExpiredJWTContextKey, userID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Temporary JWT Routes: Verify the Temporary JWT with different rules if the
			if isAlternateRoute(requestPath, server.TemporaryJWTRoutes) {
				email, id, err := auth.VerifyAndParseTemporaryJWT(ctx, redisClient, authHeader)
				if err != nil {
					utils.LogDebug(ctx, "Temporary JWT validation failed", zap.Error(err))
					utils.JSONError(w, utils.Errors.Unauthorized)
					return
				}
				ctx = context.WithValue(ctx, entities.EmailFromTempJWTContextKey, email)
				ctx = context.WithValue(ctx, entities.JTIFromTempJWTContextKey, id)
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
