package sessions

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

func IsValidSession(sessionID string, exp time.Time, rdb *redis.Client) bool {
	if time.Now().After(exp) {
		return false
	}
	ctx := context.Background()
	exists, err := rdb.Exists(ctx, "session:"+sessionID).Result()
	return err == nil && exists == 1
}
