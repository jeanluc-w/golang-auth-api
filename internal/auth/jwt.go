package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"auth-api/config"
	"auth-api/internal/entities"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	jwtIssuer   = "auth-api"
	jwtAudience = "auth-app"
)

// TokenPair is the pair of tokens returned to callers after a successful
// login, signup, or refresh: a short-lived signed JWT access token and an
// opaque, long-lived refresh token (only its hash is ever persisted).
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	SessionID    string
	AccessExp    time.Time
	RefreshExp   time.Time
}

// GenerateUserTokens issues a new access JWT + opaque refresh token for a
// fully authenticated user, and records the access session in Redis.
// It does NOT persist the refresh token anywhere other than Redis — callers
// are responsible for also durably storing its hash (see postgres.CreateRefreshSession)
// so it survives a Redis flush/restart.
func GenerateUserTokens(
	ctx context.Context,
	redisClient *redis.Client,
	userID, username, role string,
	accessTTL, refreshTTL time.Duration,
) (*TokenPair, error) {
	sessionID := uuid.NewString()

	access, accessExp, err := generateAccessJWT(ctx, redisClient, sessionID, userID, username, role, accessTTL)
	if err != nil {
		return nil, err
	}

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

// RotateSessionTokens issues a new access JWT and a new opaque refresh
// token for an EXISTING session ID, overwriting that session's Redis
// entries in place. Unlike GenerateUserTokens (which always mints a brand
// new session), this is used by the refresh-token flow to rotate an
// already-authenticated session's tokens without changing its identity —
// the session ID is what both Postgres and Redis key the session on.
func RotateSessionTokens(
	ctx context.Context,
	redisClient *redis.Client,
	sessionID, userID, username, role string,
	accessTTL, refreshTTL time.Duration,
) (*TokenPair, error) {
	access, accessExp, err := generateAccessJWT(ctx, redisClient, sessionID, userID, username, role, accessTTL)
	if err != nil {
		return nil, err
	}

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

// generateAccessJWT signs a new access JWT for the given session and
// records the session's existence in Redis so it can be revoked/checked
// independently of the JWT's own expiration.
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
			Issuer:    jwtIssuer,
			Audience:  jwt.ClaimStrings{jwtAudience},
			ID:        sessionID,
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
		},
	}

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

// generateAndStoreRefresh creates a new opaque refresh token and stores only
// its hash in Redis, keyed by session ID.
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

	key := "refresh:" + sessionID
	if err := redisClient.Set(ctx, key, hash, time.Until(exp)).Err(); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to set refresh in redis: %w", err)
	}

	return raw, exp, nil
}

// randomToken returns base64url-encoded random bytes of length n.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateTemporaryJWT issues a short-lived, restricted-scope JWT used
// between email verification and signup completion. Its role is always
// "joiner" so it can never be mistaken for (or misused as) a normal access
// token by VerifyAndParseJWT.
func GenerateTemporaryJWT(ctx context.Context, redisClient *redis.Client, email string, ttl time.Duration) (string, error) {
	sessionID := uuid.NewString()
	now := time.Now()
	exp := now.Add(ttl)
	claims := entities.JWTClaims{
		Role: entities.RoleJoiner,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			Issuer:    jwtIssuer,
			Audience:  jwt.ClaimStrings{jwtAudience},
			ID:        sessionID,
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
		},
	}

	if err := GenerateTemporarySession(ctx, sessionID, exp, redisClient); err != nil {
		return "", fmt.Errorf("failed to create session in redis: %w", err)
	}

	token := jwt.NewWithClaims(config.Loaded.JWTAlgorithm, claims)
	return token.SignedString(config.Loaded.JWTPrivateKey)
}

// keyFunc resolves the public key used to verify a token's signature,
// rejecting anything signed with an algorithm other than the one this
// service issues tokens with (defends against alg-confusion attacks).
func keyFunc(t *jwt.Token) (interface{}, error) {
	if t.Method != config.Loaded.JWTAlgorithm {
		return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
	}
	return config.Loaded.JWTPublicKey, nil
}

// parseJWT parses and verifies the JWT in a Bearer Authorization header.
//
// When allowExpired is false (the normal case), the signature, issuer,
// audience, and all standard time-based claims (exp/nbf/iat) are validated
// by the JWT library and an expired or malformed token is rejected outright.
//
// When allowExpired is true, expiration is intentionally NOT enforced here
// (only the refresh-token flow uses this, to identify which session an
// already-expired access token belonged to); the caller MUST independently
// authenticate the request via the accompanying refresh token before
// trusting the returned claims for anything. Signature, issuer, and
// audience are still enforced in both modes.
func parseJWT(authHeader string, allowExpired bool) (*entities.JWTClaims, error) {
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errors.New("missing or malformed Authorization header")
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	if !allowExpired {
		token, err := jwt.ParseWithClaims(tokenStr, &entities.JWTClaims{}, keyFunc,
			jwt.WithIssuer(jwtIssuer),
			jwt.WithAudience(jwtAudience),
			jwt.WithExpirationRequired(),
		)
		if err != nil || !token.Valid {
			return nil, errors.New("invalid token")
		}
		claims, ok := token.Claims.(*entities.JWTClaims)
		if !ok {
			return nil, errors.New("invalid claims")
		}
		return claims, nil
	}

	// Expired-allowed path: skip automatic claim validation (it would reject
	// the expired token before we ever see it) but still verify the
	// signature, then manually re-check everything except expiration.
	token, err := jwt.ParseWithClaims(tokenStr, &entities.JWTClaims{}, keyFunc, jwt.WithoutClaimsValidation())
	if err != nil {
		return nil, errors.New("invalid token")
	}
	claims, ok := token.Claims.(*entities.JWTClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}
	if claims.Issuer != jwtIssuer {
		return nil, errors.New("invalid issuer")
	}
	if !hasAudience(claims, jwtAudience) {
		return nil, errors.New("invalid audience")
	}
	if claims.ExpiresAt == nil {
		return nil, errors.New("missing expiration claim")
	}
	if claims.NotBefore != nil && time.Now().Before(claims.NotBefore.Time) {
		return nil, errors.New("token not yet valid")
	}
	return claims, nil
}

func hasAudience(claims *entities.JWTClaims, want string) bool {
	for _, aud := range claims.Audience {
		if aud == want {
			return true
		}
	}
	return false
}

// VerifyAndParseJWT verifies a normal (non-expired, non-temporary) access
// JWT and checks its session is still active in Redis, returning the
// authenticated user on success.
func VerifyAndParseJWT(ctx context.Context, redisClient *redis.Client, authHeader string) (*entities.UserContext, error) {
	claims, err := parseJWT(authHeader, false)
	if err != nil {
		return nil, err
	}

	if claims.UserID == "" || claims.ID == "" || claims.Role == entities.RoleJoiner {
		return nil, errors.New("invalid claims")
	}

	if !IsValidSession(ctx, claims.ID, claims.ExpiresAt.Time, redisClient) {
		return nil, errors.New("session expired or invalid")
	}

	return &entities.UserContext{
		ID:        claims.UserID,
		Username:  claims.Username,
		Role:      claims.Role,
		SessionID: claims.ID,
	}, nil
}

// VerifyAndParseTemporaryJWT verifies a temporary ("joiner") JWT issued
// after email verification, returning the verified email and token ID.
func VerifyAndParseTemporaryJWT(ctx context.Context, redisClient *redis.Client, authHeader string) (email string, id string, err error) {
	claims, err := parseJWT(authHeader, false)
	if err != nil {
		return "", "", err
	}

	if claims.Subject == "" || claims.ID == "" || claims.Role != entities.RoleJoiner {
		return "", "", errors.New("invalid claims")
	}

	if !IsValidTemporarySession(ctx, claims.ID, claims.ExpiresAt.Time, redisClient) {
		return "", "", errors.New("session is expired or invalid")
	}

	return claims.Subject, claims.ID, nil
}

// VerifyAndParseExpiredJWT is used only by the refresh-token endpoint. It
// verifies the signature/issuer/audience of the caller's most recent access
// JWT without regard to its expiration, and returns the session and user ID
// embedded in it. This identifies which session a refresh request is for;
// it does NOT authenticate the request by itself — the refresh service must
// still validate the accompanying refresh token against the stored hash
// before honoring the request.
func VerifyAndParseExpiredJWT(ctx context.Context, authHeader string) (sessionID string, userID string, err error) {
	claims, err := parseJWT(authHeader, true)
	if err != nil {
		return "", "", err
	}

	if claims.UserID == "" || claims.ID == "" || claims.Role == entities.RoleJoiner {
		return "", "", errors.New("invalid claims")
	}

	return claims.ID, claims.UserID, nil
}
