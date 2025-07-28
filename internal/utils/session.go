package utils

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// IsValidSession checks if a session is valid based on its ID and expiration time.
func IsValidSession(sessionID string, exp time.Time, rdb *redis.Client) bool {
	if time.Now().After(exp) {
		return false
	}
	ctx := context.Background()
	exists, err := rdb.Exists(ctx, "session:"+sessionID).Result()
	return err == nil && exists == 1
}

// GenerateSession creates a new session in Redis with the given session ID and expiration time.
func GenerateSession(sessionID string, exp time.Time, rdb *redis.Client) error {
	ctx := context.Background()
	ttl := time.Until(exp)
	if ttl <= 0 {
		return nil // do not set already-expired sessions
	}
	return rdb.Set(ctx, "session:"+sessionID, "1", ttl).Err()
}
