package auth

import (
	"context"
	"testing"
	"time"

	"auth-api/config"
	"auth-api/internal/entities"
)

// TestSaveVerificationCode_TTLMatchesConfig is a fast, Docker-free
// regression test mirroring test/integration's real-Redis version of the
// same assertion: config.Loaded.OTP_TTL is already a time.Duration, so it
// must be used directly as the Redis TTL, not multiplied by time.Minute
// again (that bug produced a ~114,000-year TTL — see the doc comment on
// SaveVerificationCode). Keeping both this unit test and the integration
// one is intentional: this one guards the exact arithmetic at zero infra
// cost; the integration one proves it against a real Redis TTL clock.
func TestSaveVerificationCode_TTLMatchesConfig(t *testing.T) {
	config.Loaded = &config.Config{OTP_TTL: 10 * time.Minute}
	ctx := context.Background()
	rdb := newTestRedis(t)

	if err := SaveVerificationCode(ctx, rdb, "someone@example.com", entities.OTPMeta{
		Code:        "123456",
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		MaxAttempts: 5,
	}); err != nil {
		t.Fatalf("SaveVerificationCode: %v", err)
	}

	ttl, err := rdb.TTL(ctx, "email_code:someone@example.com").Result()
	if err != nil {
		t.Fatalf("TTL: %v", err)
	}
	if ttl <= 0 || ttl > 10*time.Minute {
		t.Fatalf("TTL = %v, want roughly 10 minutes (config.Loaded.OTP_TTL), not OTP_TTL*time.Minute", ttl)
	}
}

func TestSaveAndGetVerificationCode_RoundTrip(t *testing.T) {
	config.Loaded = &config.Config{OTP_TTL: 10 * time.Minute}
	ctx := context.Background()
	rdb := newTestRedis(t)

	now := time.Now().Truncate(time.Second)
	want := entities.OTPMeta{
		Code:        "654321",
		CreatedAt:   now,
		ExpiresAt:   now.Add(10 * time.Minute),
		Attempts:    2,
		MaxAttempts: 5,
	}

	if err := SaveVerificationCode(ctx, rdb, "round@example.com", want); err != nil {
		t.Fatalf("SaveVerificationCode: %v", err)
	}

	got, err := GetVerificationCode(ctx, rdb, "round@example.com")
	if err != nil {
		t.Fatalf("GetVerificationCode: %v", err)
	}
	if got.Code != want.Code || got.Attempts != want.Attempts || got.MaxAttempts != want.MaxAttempts {
		t.Errorf("got %+v, want %+v", *got, want)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("timestamps did not round-trip: got CreatedAt=%v ExpiresAt=%v, want CreatedAt=%v ExpiresAt=%v",
			got.CreatedAt, got.ExpiresAt, want.CreatedAt, want.ExpiresAt)
	}
}

func TestGetVerificationCode_MissingKey(t *testing.T) {
	config.Loaded = &config.Config{OTP_TTL: 10 * time.Minute}
	ctx := context.Background()
	rdb := newTestRedis(t)

	if _, err := GetVerificationCode(ctx, rdb, "never-requested@example.com"); err == nil {
		t.Error("expected an error for a missing verification code")
	}
}

func TestGetVerificationCode_MalformedJSON(t *testing.T) {
	config.Loaded = &config.Config{OTP_TTL: 10 * time.Minute}
	ctx := context.Background()
	rdb := newTestRedis(t)

	if err := rdb.Set(ctx, "email_code:bad@example.com", "not valid json", time.Minute).Err(); err != nil {
		t.Fatalf("seeding malformed value: %v", err)
	}

	if _, err := GetVerificationCode(ctx, rdb, "bad@example.com"); err == nil {
		t.Error("expected an error for malformed stored JSON")
	}
}
