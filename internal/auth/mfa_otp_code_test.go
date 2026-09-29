package auth

import (
	"context"
	"testing"
	"time"

	"auth-api/config"
	"auth-api/internal/entities"
)

func TestMFAOTPCode_RoundTrip(t *testing.T) {
	config.Loaded = &config.Config{OTP_TTL: 10 * time.Minute}
	ctx := context.Background()
	rdb := newTestRedis(t)

	now := time.Now().Truncate(time.Second)
	want := entities.OTPMeta{
		Code: "654321", CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute),
		Attempts: 1, MaxAttempts: 5,
	}

	if err := SaveMFAOTPCode(ctx, rdb, "email", "login", "user-1", want); err != nil {
		t.Fatalf("SaveMFAOTPCode: %v", err)
	}

	got, err := GetMFAOTPCode(ctx, rdb, "email", "login", "user-1")
	if err != nil {
		t.Fatalf("GetMFAOTPCode: %v", err)
	}
	if got.Code != want.Code || got.Attempts != want.Attempts || got.MaxAttempts != want.MaxAttempts {
		t.Errorf("got %+v, want %+v", *got, want)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("timestamps did not round-trip: got CreatedAt=%v ExpiresAt=%v, want CreatedAt=%v ExpiresAt=%v",
			got.CreatedAt, got.ExpiresAt, want.CreatedAt, want.ExpiresAt)
	}
}

func TestMFAOTPCode_TTLMatchesConfig(t *testing.T) {
	config.Loaded = &config.Config{OTP_TTL: 10 * time.Minute}
	ctx := context.Background()
	rdb := newTestRedis(t)

	if err := SaveMFAOTPCode(ctx, rdb, "email", "enroll", "user-1", entities.OTPMeta{
		Code: "111111", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(10 * time.Minute), MaxAttempts: 5,
	}); err != nil {
		t.Fatalf("SaveMFAOTPCode: %v", err)
	}

	ttl, err := rdb.TTL(ctx, "mfa_otp:email:enroll:user-1").Result()
	if err != nil {
		t.Fatalf("TTL: %v", err)
	}
	if ttl <= 0 || ttl > 10*time.Minute {
		t.Fatalf("TTL = %v, want roughly 10 minutes (config.Loaded.OTP_TTL)", ttl)
	}
}

func TestMFAOTPCode_Delete(t *testing.T) {
	config.Loaded = &config.Config{OTP_TTL: 10 * time.Minute}
	ctx := context.Background()
	rdb := newTestRedis(t)

	if err := SaveMFAOTPCode(ctx, rdb, "email", "login", "user-1", entities.OTPMeta{
		Code: "222222", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(10 * time.Minute), MaxAttempts: 5,
	}); err != nil {
		t.Fatalf("SaveMFAOTPCode: %v", err)
	}
	if err := DeleteMFAOTPCode(ctx, rdb, "email", "login", "user-1"); err != nil {
		t.Fatalf("DeleteMFAOTPCode: %v", err)
	}
	if _, err := GetMFAOTPCode(ctx, rdb, "email", "login", "user-1"); err == nil {
		t.Error("expected an error reading a deleted code")
	}
}

// TestMFAOTPCode_KeysAreNamespacedIndependently locks in the property the
// whole scheme depends on: channel/purpose/userID together form the key,
// so an enrollment code and a login code for the same user (or the same
// purpose across two users) never collide or overwrite each other, and
// none of them collide with the unrelated signup verification code, which
// uses its own "email_code:<email>" key format entirely.
func TestMFAOTPCode_KeysAreNamespacedIndependently(t *testing.T) {
	config.Loaded = &config.Config{OTP_TTL: 10 * time.Minute}
	ctx := context.Background()
	rdb := newTestRedis(t)

	now := time.Now()
	enroll := entities.OTPMeta{Code: "111111", CreatedAt: now, ExpiresAt: now.Add(time.Minute), MaxAttempts: 5}
	login := entities.OTPMeta{Code: "222222", CreatedAt: now, ExpiresAt: now.Add(time.Minute), MaxAttempts: 5}
	otherUser := entities.OTPMeta{Code: "333333", CreatedAt: now, ExpiresAt: now.Add(time.Minute), MaxAttempts: 5}

	if err := SaveMFAOTPCode(ctx, rdb, "email", "enroll", "user-1", enroll); err != nil {
		t.Fatalf("SaveMFAOTPCode(enroll): %v", err)
	}
	if err := SaveMFAOTPCode(ctx, rdb, "email", "login", "user-1", login); err != nil {
		t.Fatalf("SaveMFAOTPCode(login): %v", err)
	}
	if err := SaveMFAOTPCode(ctx, rdb, "email", "login", "user-2", otherUser); err != nil {
		t.Fatalf("SaveMFAOTPCode(other user): %v", err)
	}
	if err := SaveVerificationCode(ctx, rdb, "user-1", entities.OTPMeta{Code: "999999", CreatedAt: now, ExpiresAt: now.Add(time.Minute), MaxAttempts: 5}); err != nil {
		t.Fatalf("SaveVerificationCode: %v", err)
	}

	gotEnroll, err := GetMFAOTPCode(ctx, rdb, "email", "enroll", "user-1")
	if err != nil || gotEnroll.Code != "111111" {
		t.Errorf("enroll code = %+v, err=%v; want 111111", gotEnroll, err)
	}
	gotLogin, err := GetMFAOTPCode(ctx, rdb, "email", "login", "user-1")
	if err != nil || gotLogin.Code != "222222" {
		t.Errorf("login code = %+v, err=%v; want 222222", gotLogin, err)
	}
	gotOther, err := GetMFAOTPCode(ctx, rdb, "email", "login", "user-2")
	if err != nil || gotOther.Code != "333333" {
		t.Errorf("other user's login code = %+v, err=%v; want 333333", gotOther, err)
	}
	gotSignup, err := GetVerificationCode(ctx, rdb, "user-1")
	if err != nil || gotSignup.Code != "999999" {
		t.Errorf("unrelated signup verification code = %+v, err=%v; want 999999 (must not collide with mfa_otp: keys)", gotSignup, err)
	}
}

func TestMFAOTPCode_MissingKey(t *testing.T) {
	config.Loaded = &config.Config{OTP_TTL: 10 * time.Minute}
	ctx := context.Background()
	rdb := newTestRedis(t)

	if _, err := GetMFAOTPCode(ctx, rdb, "email", "login", "never-requested"); err == nil {
		t.Error("expected an error for a missing MFA OTP code")
	}
}

func TestMFAOTPCode_MalformedJSON(t *testing.T) {
	config.Loaded = &config.Config{OTP_TTL: 10 * time.Minute}
	ctx := context.Background()
	rdb := newTestRedis(t)

	if err := rdb.Set(ctx, "mfa_otp:email:login:bad-user", "not valid json", time.Minute).Err(); err != nil {
		t.Fatalf("seeding malformed value: %v", err)
	}
	if _, err := GetMFAOTPCode(ctx, rdb, "email", "login", "bad-user"); err == nil {
		t.Error("expected an error for malformed stored JSON")
	}
}
