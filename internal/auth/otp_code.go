package auth

import (
	"context"
	"edibubble-api/config"
	"edibubble-api/internal/entities"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

func SaveVerificationCode(ctx context.Context, rdb *redis.Client, email string, meta entities.OTPMeta) error {
	otpTTL := config.Loaded.OTP_TTL * time.Minute
	key := fmt.Sprintf("email_code:%s", email)
	data, _ := json.Marshal(meta)
	return rdb.Set(ctx, key, data, otpTTL).Err()
}

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
