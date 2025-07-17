package auth

import (
	"edibubble-api/config"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims defines the custom JWT claims structure
type Claims struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	jwt.RegisteredClaims
}

// GenerateJWT generates a signed JWT token with custom claims
func GenerateJWT(sessionID, userID, username, email, role string, ttl time.Duration) (string, error) {
	secret := config.Loaded.JWTSecret
	if secret == "" {
		return "", errors.New("JWT secret not configured")
	}

	claims := Claims{
		SessionID: sessionID,
		UserID:    userID,
		Username:  username,
		Email:     email,
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
