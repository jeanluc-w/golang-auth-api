package auth

import (
	"context"
	"time"

	"auth-api/internal/utils"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// IsValidSession checks if there is a valid session based on the passed ID
// and expiration time. Redis errors fail closed (treated as invalid) since
// this gates authentication, but are logged so a Redis outage shows up as
// errors rather than a silent wave of "unauthorized" responses.
func IsValidSession(ctx context.Context, sessionID string, exp time.Time, rdb *redis.Client) bool {
	if time.Now().After(exp) {
		return false
	}
	exists, err := rdb.Exists(ctx, "session:"+sessionID).Result()
	if err != nil {
		utils.LogError(ctx, "Redis session lookup failed", zap.Error(err))
		return false
	}
	return exists == 1
}

// IsValidTemporarySession checks the session cache for a valid temporary
// token session based on the passed ID and expiration. See IsValidSession
// for the fail-closed error handling rationale.
func IsValidTemporarySession(ctx context.Context, sessionID string, exp time.Time, rdb *redis.Client) bool {
	if time.Now().After(exp) {
		return false
	}
	exists, err := rdb.Exists(ctx, "temporary_session:"+sessionID).Result()
	if err != nil {
		utils.LogError(ctx, "Redis temporary session lookup failed", zap.Error(err))
		return false
	}
	return exists == 1
}

// GenerateSession creates a new session in Redis with the given session ID and expiration time.
func GenerateSession(ctx context.Context, sessionID string, exp time.Time, rdb *redis.Client) error {
	ttl := time.Until(exp)
	if ttl <= 0 {
		return nil // do not set already-expired sessions
	}
	return rdb.Set(ctx, "session:"+sessionID, "1", ttl).Err()
}

// GenerateSession creates a new session in Redis with the given session ID and expiration time.
func GenerateTemporarySession(ctx context.Context, sessionID string, exp time.Time, rdb *redis.Client) error {
	ttl := time.Until(exp)
	if ttl <= 0 {
		return nil // do not set already-expired sessions
	}
	return rdb.Set(ctx, "temporary_session:"+sessionID, "1", ttl).Err()
}

func DeleteTemporarySession(ctx context.Context, sessionID string, rdb *redis.Client) error {
	return rdb.Del(ctx, "temporary_session:"+sessionID).Err()
}

// DeleteSession removes the access-token session and any associated refresh
// token from Redis. Used on logout and on refresh-token reuse detection.
func DeleteSession(ctx context.Context, sessionID string, rdb *redis.Client) error {
	return rdb.Del(ctx, "session:"+sessionID, "refresh:"+sessionID).Err()
}
