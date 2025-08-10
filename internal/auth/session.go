package auth

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// IsValidSession checks if there is a valid session based on the passed ID and expiration time.
func IsValidSession(ctx context.Context, sessionID string, exp time.Time, rdb *redis.Client) bool {
	if time.Now().After(exp) {
		return false
	}
	exists, err := rdb.Exists(ctx, "session:"+sessionID).Result()
	return err == nil && exists == 1
}

// IsValidTemporarySession checks the session cache for a valid temporary token session
// based on the passed ID and expiration
func IsValidTemporarySession(ctx context.Context, sessionID string, exp time.Time, rdb *redis.Client) bool {
	if time.Now().After(exp) {
		return false
	}
	exists, err := rdb.Exists(ctx, "temporary_session:"+sessionID).Result()
	return err == nil && exists == 1
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
	return rdb.Del(ctx, "temporary_session"+sessionID).Err()
}
