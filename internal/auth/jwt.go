package auth

import (
	"context"
	"crypto/rand"
	"edibubble-api/config"
	"edibubble-api/internal/entities"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Pair returned to callers
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	SessionID    string
	AccessExp    time.Time
	RefreshExp   time.Time
}

// Issues an access JWT + opaque refresh token (hashed in Redis).
func GenerateUserTokens(
	ctx context.Context,
	redisClient *redis.Client,
	userID, username, role string,
	accessTTL, refreshTTL time.Duration,
) (*TokenPair, error) {
	// Create session id
	sessionID := uuid.NewString()

	// Access token and session in Redis
	access, accessExp, err := generateAccessJWT(ctx, redisClient, sessionID, userID, username, role, accessTTL)
	if err != nil {
		return nil, err
	}

	// 3) Refresh token , hash & persist in Redis
	refresh, refreshExp, err := generateAndStoreRefresh(ctx, redisClient, sessionID, refreshTTL)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
		SessionID:    sessionID,
		AccessExp:    accessExp,
		RefreshExp:   refreshExp,
	}, nil
}

// Generate an authentication JWT token with our custom claims for normal users
// and store the session in Redis
func generateAccessJWT(
	ctx context.Context,
	redisClient *redis.Client,
	sessionID, userID, username, role string,
	ttl time.Duration,
) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(ttl)

	claims := entities.JWTClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    "edibubble-api",
			Audience:  jwt.ClaimStrings{"edibubble-app"},
			ID:        sessionID,
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
		},
	}

	// Store short-lived access session in Redis by sessionId
	if err := GenerateSession(ctx, sessionID, exp, redisClient); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create access session in redis: %w", err)
	}

	tok := jwt.NewWithClaims(config.Loaded.JWTAlgorithm, claims)
	signed, err := tok.SignedString(config.Loaded.JWTPrivateKey)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}

// Generate the refresh token and store its hash in Redis
func generateAndStoreRefresh(
	ctx context.Context,
	redisClient *redis.Client,
	sessionID string,
	ttl time.Duration,
) (string, time.Time, error) {
	if redisClient == nil {
		return "", time.Time{}, errors.New("redis client is nil")
	}
	raw, err := randomToken(32) // 256-bit random, base64url-encoded
	if err != nil {
		return "", time.Time{}, err
	}
	hash := HashRefreshToken(raw)
	exp := time.Now().Add(ttl)

	// Store the refresh token in the redis for easy access
	key := "refresh:" + sessionID
	if err := redisClient.Set(ctx, key, hash, time.Until(exp)).Err(); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to set refresh in redis: %w", err)
	}

	return raw, exp, nil
}

// Returns base64url-encoded random bytes of length n
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Generate a temporary JWT token with our custom claims
func GenerateTemporaryJWT(ctx context.Context, redisClient *redis.Client, email string, ttl time.Duration) (string, error) {
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
	if err := GenerateTemporarySession(ctx, sessionID, exp, redisClient); err != nil {
		return "", fmt.Errorf("failed to create session in redis: %w", err)
	}

	// Sign and return the JWT
	token := jwt.NewWithClaims(config.Loaded.JWTAlgorithm, claims)
	return token.SignedString(config.Loaded.JWTPrivateKey)
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
		if t.Method != config.Loaded.JWTAlgorithm {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return config.Loaded.JWTPublicKey, nil
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

	// Check expiration time on it
	if claims.ExpiresAt == nil || time.Now().After(claims.ExpiresAt.Time) {
		return nil, errors.New("token expired")
	}

	return claims, nil
}

// Verify the JWT token and return the User data structure when succesful
func VerifyAndParseJWT(ctx context.Context, redisClient *redis.Client, authHeader string) (*entities.UserContext, error) {
	// Extract the claims from the token
	claims, err := parseJWT(authHeader)
	if err != nil {
		return nil, err
	}

	// Validate the custom user claims
	if claims.UserID == "" || claims.ID == "" || claims.Role == "joiner" {
		return nil, errors.New("invalid claims")
	}

	// Check Redis-backed session validity
	if !IsValidSession(ctx, claims.ID, claims.ExpiresAt.Time, redisClient) {
		return nil, errors.New("session expired or invalid")
	}

	user := &entities.UserContext{
		ID:        claims.UserID,
		Username:  claims.Username,
		Role:      claims.Role,
		SessionID: claims.ID,
	}
	return user, nil
}

func VerifyAndParseTemporaryJWT(ctx context.Context, redisClient *redis.Client, authHeader string) (email string, id string, err error) {
	// Extract the claims from the token
	claims, err := parseJWT(authHeader)
	if err != nil {
		return "", "", err
	}

	// Check if the claims are valid
	if claims.Subject == "" || claims.ID == "" || claims.Role != "joiner" {
		return "", "", errors.New("invalid claims")
	}

	// Check if the session is valid (i.e. in the Redis)
	if !IsValidTemporarySession(ctx, claims.ID, claims.ExpiresAt.Time, redisClient) {
		return "", "", errors.New("session is expired or invalid")
	}

	// Return the email from the Subject claim
	return claims.Subject, claims.ID, nil
}

func VerifyAndParseExpiredJWT(ctx context.Context, redisClient *redis.Client, db *pgxpool.Pool, authHeader string) (string, error) {
	// Extract the claims from the token
	claims, err := parseJWT(authHeader)

	// If the error isn't token expired, forward the error.
	// If the error was empty, return an error that the token isn't expired
	if err != errors.New("token expired") {
		return "", err
	} else if err == nil {
		return "", errors.New("token is valid and not expired")
	}

	// Check if the claims are valid
	if claims.UserID == "" || claims.ID == "" || claims.Role == "joiner" {
		return "", errors.New("invalid claims")
	}

	return claims.ID, nil
}
