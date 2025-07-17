package middleware

import (
	"context"
	"edibubble-api/config"
	"edibubble-api/internal/models"
	"edibubble-api/internal/utils"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
		// Verify the auth header is in Authorization Token format
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			utils.JSONError(w, http.StatusUnauthorized, "Missing or malformed Authorization header")
			return
		}

		// Parse the JWT token from the header
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return []byte(config.Loaded.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			utils.JSONError(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			utils.JSONError(w, http.StatusUnauthorized, "Invalid claims")
			return
		}

		// Extract claims
		sessionID, _ := claims["session_id"].(string)
		userID, _ := claims["user_id"].(string)
		username, _ := claims["username"].(string)
		email, _ := claims["email"].(string)
		role, _ := claims["role"].(string)
		expFloat, ok := claims["exp"].(float64)
		if !ok {
			utils.JSONError(w, http.StatusUnauthorized, "Missing expiration claim")
			return
		}
		exp := time.Unix(int64(expFloat), 0)

		// Verify the essential claims are there
		if userID == "" || sessionID == "" {
			utils.JSONError(w, http.StatusUnauthorized, "Missing token claims")
			return
		}

		// Verify session exists and isn't revoked
		if !utils.IsValidSession(sessionID, exp, config.Loaded.RedisClient) {
			utils.JSONError(w, http.StatusUnauthorized, "Session expired or invalid")
			return
		}

		user := &models.UserContext{
			ID:        userID,
			Username:  username,
			Email:     email,
			Role:      role,
			SessionID: sessionID,
		}

		ctx := context.WithValue(r.Context(), models.UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
