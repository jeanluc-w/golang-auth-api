package integration

import (
	"context"
	"net/http"
	"testing"
	"time"

	"auth-api/internal/auth"
	"auth-api/internal/db/postgres"
	"auth-api/internal/services"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// userUUID resolves a services-layer string user ID (as returned by Login,
// CompleteEmailJoin, etc.) to the pgtype.UUID the generated postgres queries
// expect.
func userUUID(t *testing.T, id string) pgtype.UUID {
	t.Helper()
	parsed, err := uuid.Parse(id)
	if err != nil {
		t.Fatalf("uuid.Parse(%q): %v", id, err)
	}
	return pgtype.UUID{Bytes: parsed, Valid: true}
}

// seedPasswordReset inserts a password_resets row directly (bypassing
// RequestPasswordReset and its email-sending) for a known raw token, the
// same shortcut signUpTestUser takes for OTP codes — it isolates
// ResetPassword's own behavior from RequestPasswordReset's.
func seedPasswordReset(t *testing.T, ctx context.Context, userID pgtype.UUID, rawToken string, expiresAt time.Time) {
	t.Helper()
	if _, err := postgres.New(testDB).CreatePasswordReset(ctx, postgres.CreatePasswordResetParams{
		UserID:     userID,
		ResetToken: auth.HashOpaqueToken(rawToken),
		ExpiresAt:  pgtype.Timestamptz{Time: expiresAt, Valid: true},
		Source:     postgres.ResetSourceWeb,
	}); err != nil {
		t.Fatalf("CreatePasswordReset: %v", err)
	}
}

func TestRequestPasswordReset_HappyPath(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signUpTestUser(t, ctx, email, "resetreqhappy", "correct horse battery staple")
	fakeResend, callCount := newFakeResendClient(t, http.StatusOK)

	if errDetail := services.RequestPasswordReset(ctx, testDB, testRedis, fakeResend, email, "web"); errDetail != nil {
		t.Fatalf("RequestPasswordReset: %+v", errDetail)
	}
	if callCount.Load() != 1 {
		t.Errorf("fake email server received %d requests, want 1", callCount.Load())
	}
}

// TestRequestPasswordReset_UnknownEmail_SameResponse is the core
// enumeration-resistance test: an unknown email must get the exact same nil
// (success) response as a known one, and — unlike the response — internal
// behavior (no email actually sent) is allowed and expected to differ.
func TestRequestPasswordReset_UnknownEmail_SameResponse(t *testing.T) {
	ctx := context.Background()
	fakeResend, callCount := newFakeResendClient(t, http.StatusOK)

	if errDetail := services.RequestPasswordReset(ctx, testDB, testRedis, fakeResend, uniqueEmail(t), "web"); errDetail != nil {
		t.Fatalf("RequestPasswordReset for unknown email should return nil (generic success), got: %+v", errDetail)
	}
	if callCount.Load() != 0 {
		t.Errorf("expected no email to be sent for an unknown email, got %d calls", callCount.Load())
	}
}

func TestRequestPasswordReset_Cooldown(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signUpTestUser(t, ctx, email, "resetreqcooldown", "correct horse battery staple")
	fakeResend, callCount := newFakeResendClient(t, http.StatusOK)

	if errDetail := services.RequestPasswordReset(ctx, testDB, testRedis, fakeResend, email, "web"); errDetail != nil {
		t.Fatalf("first RequestPasswordReset: %+v", errDetail)
	}
	if errDetail := services.RequestPasswordReset(ctx, testDB, testRedis, fakeResend, email, "web"); errDetail != nil {
		t.Fatalf("second (cooldown) RequestPasswordReset should still return nil, got: %+v", errDetail)
	}
	if callCount.Load() != 1 {
		t.Errorf("expected the cooldown to suppress the second email, got %d calls", callCount.Load())
	}
}

func TestRequestPasswordReset_InvalidEmailFormat(t *testing.T) {
	ctx := context.Background()
	fakeResend, _ := newFakeResendClient(t, http.StatusOK)

	if errDetail := services.RequestPasswordReset(ctx, testDB, testRedis, fakeResend, "not-an-email", "web"); errDetail == nil {
		t.Fatal("expected an error for a malformed email")
	}
}

func TestRequestPasswordReset_MobileSource(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signup := signUpTestUser(t, ctx, email, "resetreqmobile", "correct horse battery staple")
	fakeResend, callCount := newFakeResendClient(t, http.StatusOK)

	if errDetail := services.RequestPasswordReset(ctx, testDB, testRedis, fakeResend, email, "mobile"); errDetail != nil {
		t.Fatalf("RequestPasswordReset: %+v", errDetail)
	}
	if callCount.Load() != 1 {
		t.Errorf("fake email server received %d requests, want 1", callCount.Load())
	}

	var source string
	if err := testDB.QueryRow(ctx, `SELECT source::text FROM password_resets WHERE user_id = $1`, userUUID(t, signup.UserID)).Scan(&source); err != nil {
		t.Fatalf("querying stored source: %v", err)
	}
	if source != "mobile" {
		t.Errorf("stored source = %q, want %q", source, "mobile")
	}
}

func TestRequestPasswordReset_InvalidSource_StillGeneric(t *testing.T) {
	ctx := context.Background()
	fakeResend, callCount := newFakeResendClient(t, http.StatusOK)

	// An invalid source is a caller bug, not an enumeration probe, so it's
	// fine (and expected) for it to return a distinct error — see
	// parsePasswordResetSource's doc comment. This just locks in that
	// "admin" specifically is rejected from this public endpoint.
	if errDetail := services.RequestPasswordReset(ctx, testDB, testRedis, fakeResend, uniqueEmail(t), "admin"); errDetail == nil {
		t.Error("expected source=admin to be rejected on the public request-reset endpoint")
	}
	if errDetail := services.RequestPasswordReset(ctx, testDB, testRedis, fakeResend, uniqueEmail(t), "carrier-pigeon"); errDetail == nil {
		t.Error("expected an unrecognized source value to be rejected")
	}
	if callCount.Load() != 0 {
		t.Errorf("expected no email to be sent for a rejected source, got %d calls", callCount.Load())
	}
}

// TestResetPassword_FullFlow_RevokesExistingSessions is the main end-to-end
// test: after a reset, the old password must stop working, the new one must
// work, and every session that existed before the reset — both the
// Postgres record (checked by refresh) and the Redis entry (checked by
// access-token verification) — must be dead.
func TestResetPassword_FullFlow_RevokesExistingSessions(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const oldPassword = "correct horse battery staple"
	const newPassword = "new correct horse battery staple"

	signup := signUpTestUser(t, ctx, email, "resetflowuser", oldPassword)

	login, errDetail := services.Login(ctx, testDB, testRedis, email, oldPassword)
	if errDetail != nil {
		t.Fatalf("Login: %+v", errDetail)
	}
	user, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+login.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAndParseJWT: %v", err)
	}
	sessionID := user.SessionID

	const rawToken = "test-reset-token-full-flow"
	seedPasswordReset(t, ctx, userUUID(t, signup.UserID), rawToken, time.Now().Add(30*time.Minute))

	if errDetail := services.ResetPassword(ctx, testDB, testRedis, rawToken, newPassword, newPassword); errDetail != nil {
		t.Fatalf("ResetPassword: %+v", errDetail)
	}

	if _, errDetail := services.Login(ctx, testDB, testRedis, email, oldPassword); errDetail == nil {
		t.Error("old password still works after reset")
	}
	if _, errDetail := services.Login(ctx, testDB, testRedis, email, newPassword); errDetail != nil {
		t.Errorf("new password doesn't work after reset: %+v", errDetail)
	}

	if _, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+login.AccessToken); err == nil {
		t.Error("pre-reset access token still valid after reset (Redis session should be gone)")
	}
	if _, errDetail := services.RefreshToken(ctx, testDB, testRedis, sessionID, login.UserID, login.RefreshToken); errDetail == nil {
		t.Error("pre-reset refresh token still works after reset (Postgres session should be revoked)")
	}
}

func TestResetPassword_TokenCannotBeReused(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signup := signUpTestUser(t, ctx, email, "resetreuseuser", "correct horse battery staple")

	const rawToken = "test-reset-token-reuse"
	seedPasswordReset(t, ctx, userUUID(t, signup.UserID), rawToken, time.Now().Add(30*time.Minute))

	if errDetail := services.ResetPassword(ctx, testDB, testRedis, rawToken, "first new password!", "first new password!"); errDetail != nil {
		t.Fatalf("first ResetPassword: %+v", errDetail)
	}
	if errDetail := services.ResetPassword(ctx, testDB, testRedis, rawToken, "second new password!", "second new password!"); errDetail == nil {
		t.Error("expected reusing an already-consumed reset token to fail")
	}
}

func TestResetPassword_ExpiredToken(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signup := signUpTestUser(t, ctx, email, "resetexpireduser", "correct horse battery staple")

	const rawToken = "test-reset-token-expired"
	seedPasswordReset(t, ctx, userUUID(t, signup.UserID), rawToken, time.Now().Add(-time.Minute))

	if errDetail := services.ResetPassword(ctx, testDB, testRedis, rawToken, "some new password!", "some new password!"); errDetail == nil {
		t.Error("expected an expired reset token to be rejected")
	}
}

func TestResetPassword_UnknownToken(t *testing.T) {
	ctx := context.Background()
	if errDetail := services.ResetPassword(ctx, testDB, testRedis, "this-token-was-never-issued", "some new password!", "some new password!"); errDetail == nil {
		t.Error("expected an unknown reset token to be rejected")
	}
}

func TestResetPassword_PasswordMismatch(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signup := signUpTestUser(t, ctx, email, "resetmismatchuser", "correct horse battery staple")

	const rawToken = "test-reset-token-mismatch"
	seedPasswordReset(t, ctx, userUUID(t, signup.UserID), rawToken, time.Now().Add(30*time.Minute))

	if errDetail := services.ResetPassword(ctx, testDB, testRedis, rawToken, "new password one", "a different password"); errDetail == nil {
		t.Error("expected mismatched new/confirm passwords to be rejected")
	}
}

func TestResetPassword_InvalidNewPasswordFormat(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signup := signUpTestUser(t, ctx, email, "resetinvalidformatuser", "correct horse battery staple")

	const rawToken = "test-reset-token-invalid-format"
	seedPasswordReset(t, ctx, userUUID(t, signup.UserID), rawToken, time.Now().Add(30*time.Minute))

	if errDetail := services.ResetPassword(ctx, testDB, testRedis, rawToken, "short", "short"); errDetail == nil {
		t.Error("expected a too-short new password to be rejected")
	}
}
