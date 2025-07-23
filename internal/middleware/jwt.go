package middleware

import (
	"context"
	"edibubble-api/internal/auth"
	"edibubble-api/internal/models"
	"edibubble-api/internal/server"
	"edibubble-api/internal/utils"
	"net/http"
	"strings"
)

var openRoutePrefixes = []string{
	server.V1_HealthCheck,
	server.V1_StartEmailVerification,
	server.V1_VerifyEmail,
}

func isOpenRoute(path string) bool {
	for _, prefix := range openRoutePrefixes {
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

		ctx := r.Context()
		// Verify the JWT token and get back the user object if successful
		user, err := auth.VerifyJWT(r.Header.Get("Authorization"))
		if err != nil {
			utils.JSONError(w, http.StatusUnauthorized, err.Error())
			return
		}

		ctx = context.WithValue(ctx, models.UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
