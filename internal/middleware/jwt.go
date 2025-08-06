package middleware

import (
	"context"
	"edibubble-api/internal/auth"
	"edibubble-api/internal/entities"
	"edibubble-api/internal/server"
	"edibubble-api/internal/utils"
	"net/http"
	"strings"

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

func JWTMiddleware(next http.Handler) http.Handler {
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
			email, err := auth.VerifyTemporaryJWT(authHeader)
			if err != nil {
				utils.LogDebug(ctx, "Temporary JWT validation failed", zap.Error(err))
				utils.JSONError(w, utils.Errors.Unauthorized)
				return
			}
			ctx = context.WithValue(ctx, entities.EmailFromDecodedTempJWTKey, email)
			next.ServeHTTP(w, r.WithContext(ctx))
		}

		// Verify the JWT token and get back the user object if successful
		user, err := auth.VerifyJWT(authHeader)
		if err != nil {
			utils.LogDebug(ctx, "JWT validation failed", zap.Error(err))
			utils.JSONError(w, utils.Errors.Unauthorized)
			return
		}

		ctx = context.WithValue(ctx, entities.UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
