package auth

import (
	"auth-api/config"
	"auth-api/internal/entities"
	"context"
	"encoding/json"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// SaveVerificationCode stores the email verification OTP in Redis under a
// TTL matching config.Loaded.OTP_TTL. Note OTP_TTL is already a
// time.Duration (e.g. 10*time.Minute) — it must NOT be multiplied by
// time.Minute again here, or the Redis key's TTL balloons to an
// astronomically large value and the key effectively never expires (it
// previously did exactly this: OTP_TTL*time.Minute on a 10-minute duration
// produces a TTL of roughly 114,000 years). The app-level expiry check in
// VerifyEmailCode still rejects stale codes either way, but a key that
// never expires is a permanent per-attempt memory leak in Redis.
func SaveVerificationCode(ctx context.Context, rdb *redis.Client, email string, meta entities.OTPMeta) error {
	key := fmt.Sprintf("email_code:%s", email)
	data, _ := json.Marshal(meta)
	return rdb.Set(ctx, key, data, config.Loaded.OTP_TTL).Err()
}

// GetVerificationCode retrieves and decodes the stored OTP metadata for an
// email, if present.
func GetVerificationCode(ctx context.Context, rdb *redis.Client, email string) (*entities.OTPMeta, error) {
	key := fmt.Sprintf("email_code:%s", email)
	val, err := rdb.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	var meta entities.OTPMeta
	if err := json.Unmarshal([]byte(val), &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}
