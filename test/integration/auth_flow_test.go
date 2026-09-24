package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"auth-api/internal/auth"
	"auth-api/internal/db/postgres"
	"auth-api/internal/entities"
	"auth-api/internal/services"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/argon2"
)

// signUpTestUser drives the real signup flow (verification code -> temp JWT
// -> account creation) exactly as the HTTP handlers do, except it seeds the
// verification code directly instead of going through the Resend email
// client, since sending real email is out of scope for these tests.
func signUpTestUser(t *testing.T, ctx context.Context, email, username, password string) *services.EmailJoinResult {
	t.Helper()

	const code = "123456"
	now := time.Now()
	if err := auth.SaveVerificationCode(ctx, testRedis, email, entities.OTPMeta{
		Code:        code,
		CreatedAt:   now,
		ExpiresAt:   now.Add(10 * time.Minute),
		Attempts:    0,
		MaxAttempts: 5,
	}); err != nil {
		t.Fatalf("SaveVerificationCode: %v", err)
	}

	verifyResult, errDetail := services.VerifyEmailCode(ctx, testRedis, email, code)
	if errDetail != nil {
		t.Fatalf("VerifyEmailCode: %+v", errDetail)
	}

	gotEmail, jti, err := auth.VerifyAndParseTemporaryJWT(ctx, testRedis, "Bearer "+verifyResult.Token)
	if err != nil {
		t.Fatalf("VerifyAndParseTemporaryJWT: %v", err)
	}
	if gotEmail != email {
		t.Fatalf("temp JWT email = %q, want %q", gotEmail, email)
	}

	joinCtx := context.WithValue(ctx, entities.EmailFromTempJWTContextKey, gotEmail)
	joinCtx = context.WithValue(joinCtx, entities.JTIFromTempJWTContextKey, jti)

	result, errDetail := services.CompleteEmailJoin(joinCtx, testDB, testRedis, username, password, password)
	if errDetail != nil {
		t.Fatalf("CompleteEmailJoin: %+v", errDetail)
	}
	return result
}

func uniqueEmail(t *testing.T) string {
	return fmt.Sprintf("%s@example.com", uuid.NewString())
}

// TestSaveVerificationCode_TTLMatchesConfig is a regression test for a bug
// where SaveVerificationCode computed the Redis TTL as
// config.Loaded.OTP_TTL * time.Minute instead of just config.Loaded.OTP_TTL
// (which is already a time.Duration) — on the default 10-minute OTP_TTL
// that produced a TTL of roughly 114,000 years, i.e. the key never expired.
func TestSaveVerificationCode_TTLMatchesConfig(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)

	if err := auth.SaveVerificationCode(ctx, testRedis, email, entities.OTPMeta{
		Code:        "123456",
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		MaxAttempts: 5,
	}); err != nil {
		t.Fatalf("SaveVerificationCode: %v", err)
	}

	ttl, err := testRedis.TTL(ctx, "email_code:"+email).Result()
	if err != nil {
		t.Fatalf("TTL: %v", err)
	}
	// config.Loaded.OTP_TTL is 10 minutes in the test config; allow slack
	// for test execution time but this should be nowhere near, say, a day.
	if ttl <= 0 || ttl > 15*time.Minute {
		t.Fatalf("verification code TTL = %v, want roughly 10 minutes (config.Loaded.OTP_TTL)", ttl)
	}
}

func TestSignupLoginRefreshLogout_HappyPath(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"

	signup := signUpTestUser(t, ctx, email, "happypathuser", password)
	if signup.AccessToken == "" || signup.RefreshToken == "" {
		t.Fatal("signup did not return tokens")
	}

	login, errDetail := services.Login(ctx, testDB, testRedis, email, password)
	if errDetail != nil {
		t.Fatalf("Login: %+v", errDetail)
	}
	if login.UserID != signup.UserID {
		t.Fatalf("login user id = %s, want %s", login.UserID, signup.UserID)
	}

	user, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+login.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAndParseJWT on fresh access token: %v", err)
	}
	sessionID := user.SessionID

	refreshed, errDetail := services.RefreshToken(ctx, testDB, testRedis, sessionID, login.UserID, login.RefreshToken)
	if errDetail != nil {
		t.Fatalf("RefreshToken: %+v", errDetail)
	}
	if refreshed.RefreshToken == login.RefreshToken {
		t.Fatal("refresh did not rotate the refresh token")
	}

	if _, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+refreshed.AccessToken); err != nil {
		t.Fatalf("VerifyAndParseJWT on refreshed access token: %v", err)
	}

	if errDetail := services.Logout(ctx, testDB, testRedis, sessionID); errDetail != nil {
		t.Fatalf("Logout: %+v", errDetail)
	}

	if _, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+refreshed.AccessToken); err == nil {
		t.Fatal("access token still valid after logout")
	}
	if _, errDetail := services.RefreshToken(ctx, testDB, testRedis, sessionID, login.UserID, refreshed.RefreshToken); errDetail == nil {
		t.Fatal("refresh still succeeded after logout")
	}
}

func TestLogin_UnknownEmailAndWrongPassword_SameError(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signUpTestUser(t, ctx, email, "wrongpassuser", "correct horse battery staple")

	_, unknownErr := services.Login(ctx, testDB, testRedis, uniqueEmail(t), "whatever password here")
	_, wrongPassErr := services.Login(ctx, testDB, testRedis, email, "the wrong password entirely")

	if unknownErr == nil || wrongPassErr == nil {
		t.Fatal("expected both attempts to fail")
	}
	if unknownErr.Code != wrongPassErr.Code {
		t.Fatalf("error codes differ: unknown email=%s wrong password=%s (this leaks account existence)", unknownErr.Code, wrongPassErr.Code)
	}
}

func TestLogin_LockoutAfterMaxFailedAttempts(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"
	signUpTestUser(t, ctx, email, "lockoutuser", password)

	// config.Loaded.LoginMaxFailedAttempts is 3 in the test config.
	for i := 0; i < 3; i++ {
		_, errDetail := services.Login(ctx, testDB, testRedis, email, "wrong password attempt")
		if errDetail == nil {
			t.Fatalf("attempt %d: expected failure", i)
		}
	}

	// Even the CORRECT password should now be rejected as locked.
	_, errDetail := services.Login(ctx, testDB, testRedis, email, password)
	if errDetail == nil {
		t.Fatal("expected account to be locked")
	}
	if errDetail.Code != "account_locked" {
		t.Fatalf("error code = %s, want account_locked", errDetail.Code)
	}

	// config.Loaded.LoginLockDuration is 2s in the test config.
	time.Sleep(2100 * time.Millisecond)

	login, errDetail := services.Login(ctx, testDB, testRedis, email, password)
	if errDetail != nil {
		t.Fatalf("expected login to succeed after lock window passed: %+v", errDetail)
	}
	if login.UserID == "" {
		t.Fatal("expected a user id back")
	}
}

func TestRefreshToken_ReuseIsDetectedAndKillsSession(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"
	signUpTestUser(t, ctx, email, "reuseuser", password)

	login, errDetail := services.Login(ctx, testDB, testRedis, email, password)
	if errDetail != nil {
		t.Fatalf("Login: %+v", errDetail)
	}
	user, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+login.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAndParseJWT: %v", err)
	}
	sessionID := user.SessionID
	staleRefreshToken := login.RefreshToken

	first, errDetail := services.RefreshToken(ctx, testDB, testRedis, sessionID, login.UserID, staleRefreshToken)
	if errDetail != nil {
		t.Fatalf("first refresh: %+v", errDetail)
	}

	// Reusing the now-superseded refresh token should fail...
	_, errDetail = services.RefreshToken(ctx, testDB, testRedis, sessionID, login.UserID, staleRefreshToken)
	if errDetail == nil {
		t.Fatal("expected reuse of a rotated-out refresh token to fail")
	}

	// ...and should have killed the session entirely, so even the CURRENT
	// (valid, never-used) refresh token from the first rotation no longer works.
	_, errDetail = services.RefreshToken(ctx, testDB, testRedis, sessionID, login.UserID, first.RefreshToken)
	if errDetail == nil {
		t.Fatal("expected the entire session to be revoked after refresh-token reuse was detected")
	}
}

func TestLogin_RehashesLegacyPasswordHashOnSuccess(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"
	signUpTestUser(t, ctx, email, "rehashuser", password)

	q := postgres.New(testDB)
	before, err := q.GetEmailAuthByEmail(ctx, email)
	if err != nil {
		t.Fatalf("GetEmailAuthByEmail: %v", err)
	}

	// Overwrite the stored hash with one computed under the retired
	// ("test-legacy") pepper, as if it predated a pepper rotation.
	legacyHash, err := hashUnderPepper(password, "test-legacy", "ZmVkY2JhOTg3NjU0MzIxMA==")
	if err != nil {
		t.Fatalf("hashUnderPepper: %v", err)
	}
	if err := q.UpdatePasswordHash(ctx, postgres.UpdatePasswordHashParams{
		PasswordHash: pgtype.Text{String: legacyHash, Valid: true},
		ID:           before.IdentityID,
	}); err != nil {
		t.Fatalf("UpdatePasswordHash: %v", err)
	}

	if _, errDetail := services.Login(ctx, testDB, testRedis, email, password); errDetail != nil {
		t.Fatalf("Login with legacy-pepper hash: %+v", errDetail)
	}

	after, err := q.GetEmailAuthByEmail(ctx, email)
	if err != nil {
		t.Fatalf("GetEmailAuthByEmail (after): %v", err)
	}
	if after.PasswordHash.String == legacyHash {
		t.Fatal("password hash was not rehashed under the active pepper after login")
	}
	if !strings.Contains(after.PasswordHash.String, "pepper=test-active") {
		t.Fatalf("rehashed password does not reference the active pepper: %s", after.PasswordHash.String)
	}

	// The rehashed value must still authenticate the user going forward.
	if _, errDetail := services.Login(ctx, testDB, testRedis, email, password); errDetail != nil {
		t.Fatalf("Login after rehash: %+v", errDetail)
	}
}

// hashUnderPepper replicates auth.HashPasswordPHC's PHC format for an
// arbitrary (pepper id, base64 pepper) pair, independent of which pepper is
// currently configured as active. It exists only to seed realistic "hashed
// under a since-rotated-out pepper" fixtures for the rehash-on-login test;
// production code always hashes under the active pepper.
func hashUnderPepper(password, pepperID, pepperB64 string) (string, error) {
	const (
		argonTime    uint32 = 2
		argonMemory  uint32 = 128 * 1024
		argonThreads uint8  = 4
		saltLen             = 16
		keyLen              = 32
	)
	pepper, err := base64.StdEncoding.DecodeString(pepperB64)
	if err != nil {
		return "", err
	}
	salt := make([]byte, saltLen)
	for i := range salt {
		salt[i] = byte(i + 1) // fixed, non-zero salt is fine for a test fixture
	}
	key := argon2.IDKey([]byte(password+string(pepper)), salt, argonTime, argonMemory, argonThreads, keyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d,pepper=%s$%s$%s",
		argonMemory, argonTime, argonThreads, pepperID,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}
