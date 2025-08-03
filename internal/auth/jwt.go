package auth

import (
	"edibubble-api/config"
	"edibubble-api/internal/entities"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TODO: Change signing algorithms

// Generate a signed JWT token with our custom claims
func GenerateJWT(sessionID, userID, username, email, role string, ttl time.Duration) (string, error) {
	secret := config.Loaded.JWTSecret
	if secret == "" {
		return "", errors.New("JWT secret not configured")
	}

	// Generate the Token
	now := time.Now()
	exp := now.Add(ttl)
	claims := entities.JWTClaims{
		SessionID: sessionID,
		UserID:    userID,
		Username:  username,
		Role:      role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    "edibubble-api",
			Audience:  jwt.ClaimStrings{"edibubble-app"},
			ID:        uuid.NewString(),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
		},
	}

	// Create the session in Redis
	if err := GenerateTemporarySession(sessionID, exp, config.Loaded.RedisClient); err != nil {
		return "", fmt.Errorf("failed to create session in redis: %w", err)
	}

	// Sign and return the JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// Generate a temporary JWT token with our custom claims
func GenerateTemporaryJWT(email string, ttl time.Duration) (string, error) {
	secret := config.Loaded.JWTSecret
	if secret == "" {
		return "", errors.New("JWT secret not configured")
	}

	// Generate the token
	sessionID := uuid.NewString()
	now := time.Now()
	exp := now.Add(ttl)
	claims := entities.JWTClaims{
		Role: "joiner",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			Issuer:    "edibubble-api",
			Audience:  jwt.ClaimStrings{"edibubble-app"},
			ID:        sessionID,
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
		},
	}

	// Create session in redis
	if err := GenerateTemporarySession(sessionID, exp, config.Loaded.RedisClient); err != nil {
		return "", fmt.Errorf("failed to create session in redis: %w", err)
	}

	// Sign and return the JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// Parse the JWT token from the Authorization header
// Returns the JWTClaims if successful, or an error if parsing fails
func parseJWT(authHeader string) (*entities.JWTClaims, error) {
	// Check if the Authorization header is present and formatted correctly
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errors.New("missing or malformed Authorization header")
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	// Parse the token with our custom claims
	token, err := jwt.ParseWithClaims(tokenStr, &entities.JWTClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(config.Loaded.JWTSecret), nil
	})

	// Check if the token parsed successfully
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Extract the claims from the token
	claims, ok := token.Claims.(*entities.JWTClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	// Check expiration time on it
	if claims.ExpiresAt == nil || time.Now().After(claims.ExpiresAt.Time) {
		return nil, errors.New("token expired")
	}

	// Validate the audience claim
	audValid := false
	for _, aud := range claims.RegisteredClaims.Audience {
		if aud == "edibubble-app" {
			audValid = true
			break
		}
	}
	if !audValid {
		return nil, errors.New("invalid audience")
	}

	// Validate the Issuer claim
	if claims.RegisteredClaims.Issuer != "edibubble-api" {
		return nil, errors.New("invalid issuer")
	}

	return claims, nil
}

// Verify the JWT token and return the User data structure when succesful
func VerifyJWT(authHeader string) (*entities.UserContext, error) {
	// Extract the claims from the token
	claims, err := parseJWT(authHeader)
	if err != nil {
		return nil, err
	}

	// Validate the custom user claims
	if claims.UserID == "" || claims.SessionID == "" {
		return nil, errors.New("invalid claims")
	}

	// Check Redis-backed session validity
	if !IsValidSession(claims.SessionID, claims.ExpiresAt.Time, config.Loaded.RedisClient) {
		return nil, errors.New("session expired or invalid")
	}

	user := &entities.UserContext{
		ID:        claims.UserID,
		Username:  claims.Username,
		Role:      claims.Role,
		SessionID: claims.SessionID,
	}
	return user, nil
}

func VerifyTemporaryJWT(authHeader string) (email string, err error) {
	// Extract the claims from the token
	claims, err := parseJWT(authHeader)
	if err != nil {
		return "", err
	}

	// Check if the claims are valid
	if claims.Subject == "" || claims.Role != "joiner" {
		return "", errors.New("invalid claims")
	}

	// Check if the session is valid (i.e. in the Redis)
	if !IsValidTemporarySession(claims.ID, claims.ExpiresAt.Time, config.Loaded.RedisClient) {
		return "", errors.New("session is expired or invalid")
	}

	// Return the email from the Subject claim
	return claims.Subject, nil
}
