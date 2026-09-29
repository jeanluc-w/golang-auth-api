package auth

import (
	"context"
	"encoding/json"
	"fmt"

	"auth-api/config"
	"auth-api/internal/entities"

	"github.com/redis/go-redis/v9"
)

// mfaOTPCodeKey namespaces email/SMS MFA one-time codes distinctly from
// the signup verification code (SaveVerificationCode's "email_code:<email>"
// keys) and from each other: channel is "email" or "sms", purpose is
// "enroll" (proving ownership before the factor activates) or "login"
// (the per-attempt code sent once MFA is already active). userID scopes it
// to one account regardless of purpose/channel.
func mfaOTPCodeKey(channel, purpose, userID string) string {
	return fmt.Sprintf("mfa_otp:%s:%s:%s", channel, purpose, userID)
}

// SaveMFAOTPCode stores an email/SMS MFA code under config.Loaded.OTP_TTL,
// the same TTL used for the signup verification code.
func SaveMFAOTPCode(ctx context.Context, rdb *redis.Client, channel, purpose, userID string, meta entities.OTPMeta) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return rdb.Set(ctx, mfaOTPCodeKey(channel, purpose, userID), data, config.Loaded.OTP_TTL).Err()
}

func GetMFAOTPCode(ctx context.Context, rdb *redis.Client, channel, purpose, userID string) (*entities.OTPMeta, error) {
	val, err := rdb.Get(ctx, mfaOTPCodeKey(channel, purpose, userID)).Result()
	if err != nil {
		return nil, err
	}
	var meta entities.OTPMeta
	if err := json.Unmarshal([]byte(val), &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func DeleteMFAOTPCode(ctx context.Context, rdb *redis.Client, channel, purpose, userID string) error {
	return rdb.Del(ctx, mfaOTPCodeKey(channel, purpose, userID)).Err()
}
