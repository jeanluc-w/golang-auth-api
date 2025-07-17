package middleware

import (
	"context"
	"edibubble-api/internal/auth"
	"edibubble-api/internal/models"
	"edibubble-api/internal/utils"
	"net/http"
)

var openRoutes = map[string]bool{
	"/auth/login":   true,
	"/auth/join":    true,
	"/auth/refresh": true,
	"/healthcheck":  true,
}

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ignore the routes where they are open to anyone
		if openRoutes[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		// Verify the JWT token and get back the user object if successful
		user, err := auth.VerifyJWT(r.Header.Get("Authorization"))
		if err != nil {
			utils.JSONError(w, http.StatusUnauthorized, err.Error())
			return
		}

		ctx := context.WithValue(r.Context(), models.UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
