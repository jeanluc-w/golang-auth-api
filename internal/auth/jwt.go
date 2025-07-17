package auth

import (
	"edibubble-api/config"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWT Claims
type Claims struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	jwt.RegisteredClaims
}

// Generate a signed JWT token with our custom claims
func GenerateJWT(sessionID, userID, username, email, role string, ttl time.Duration) (string, error) {
	secret := config.Loaded.JWTSecret
	if secret == "" {
		return "", errors.New("JWT secret not configured")
	}

	claims := Claims{
		SessionID: sessionID,
		UserID:    userID,
		Username:  username,
		Role:      role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "edibubble-api",
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
