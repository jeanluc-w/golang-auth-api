package auth

import (
	"edibubble-api/config"
	"edibubble-api/internal/models"
	"edibubble-api/internal/utils"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWT Claims

// Generate a signed JWT token with our custom claims
func GenerateJWT(sessionID, userID, username, email, role string, ttl time.Duration) (string, error) {
	secret := config.Loaded.JWTSecret
	if secret == "" {
		return "", errors.New("JWT secret not configured")
	}

	claims := models.Claims{
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

// Verify the JWT token and return the User data structure when succesful
func VerifyJWT(authHeader string) (*models.UserContext, error) {
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errors.New("missing or malformed Authorization header")
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.ParseWithClaims(tokenStr, &models.Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(config.Loaded.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(*models.Claims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	// Check required fields
	if claims.UserID == "" || claims.SessionID == "" {
		return nil, errors.New("missing token claims")
	}

	// Check expiration
	if claims.ExpiresAt == nil || time.Now().After(claims.ExpiresAt.Time) {
		return nil, errors.New("token expired")
	}

	// Check Redis-backed session validity
	if !utils.IsValidSession(claims.SessionID, claims.ExpiresAt.Time, config.Loaded.RedisClient) {
		return nil, errors.New("session expired or invalid")
	}

	user := &models.UserContext{
		ID:        claims.UserID,
		Username:  claims.Username,
		Role:      claims.Role,
		SessionID: claims.SessionID,
	}
	return user, nil
}
