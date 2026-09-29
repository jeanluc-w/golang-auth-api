package integration

import (
	"context"
	"testing"
	"time"

	"auth-api/internal/auth"
	"auth-api/internal/services"

	"github.com/pquerna/otp/totp"
)

// enrollAndVerifyMFA drives a full enroll->verify cycle for an existing
// user and returns the recovery codes issued on success, so tests that only
// care about "an MFA-enabled account" don't have to repeat this setup.
func enrollAndVerifyMFA(t *testing.T, ctx context.Context, userID, username string) []string {
	t.Helper()

	enrolled, errDetail := services.EnrollMFA(ctx, testDB, userID, username)
	if errDetail != nil {
		t.Fatalf("EnrollMFA: %+v", errDetail)
	}
	if enrolled.Secret == "" || enrolled.ProvisioningURI == "" {
		t.Fatal("expected a non-empty secret and provisioning URI")
	}

	code, err := totp.GenerateCode(enrolled.Secret, time.Now())
	if err != nil {
		t.Fatalf("totp.GenerateCode: %v", err)
	}

	verified, errDetail := services.VerifyMFAEnrollment(ctx, testDB, userID, code)
	if errDetail != nil {
		t.Fatalf("VerifyMFAEnrollment: %+v", errDetail)
	}
	if len(verified.RecoveryCodes) != 10 {
		t.Fatalf("got %d recovery codes, want 10 (config.Loaded.MFARecoveryCodeCount)", len(verified.RecoveryCodes))
	}
	return verified.RecoveryCodes
}

func TestMFA_EnrollVerifyDisable_Lifecycle(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signup := signUpTestUser(t, ctx, email, "mfalifecycle", "correct horse battery staple")

	enrollAndVerifyMFA(t, ctx, signup.UserID, signup.Username)

	// Enrolling again while already active must be rejected outright.
	if _, errDetail := services.EnrollMFA(ctx, testDB, signup.UserID, signup.Username); errDetail == nil {
		t.Error("expected EnrollMFA to reject enrollment when MFA is already enabled")
	}

	if errDetail := services.DisableMFA(ctx, testDB, signup.UserID, "correct horse battery staple"); errDetail != nil {
		t.Fatalf("DisableMFA: %+v", errDetail)
	}

	// Disabling again (nothing to disable) must fail cleanly, not panic.
	if errDetail := services.DisableMFA(ctx, testDB, signup.UserID, "correct horse battery staple"); errDetail == nil {
		t.Error("expected DisableMFA to fail when MFA isn't enabled")
	}

	// Re-enrollment after a clean disable must work (fresh INSERT, not a
	// conflict against a row that no longer exists).
	enrollAndVerifyMFA(t, ctx, signup.UserID, signup.Username)
}

func TestMFA_VerifyEnrollment_WrongCodeRejected(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signup := signUpTestUser(t, ctx, email, "mfawrongcode", "correct horse battery staple")

	if _, errDetail := services.EnrollMFA(ctx, testDB, signup.UserID, signup.Username); errDetail != nil {
		t.Fatalf("EnrollMFA: %+v", errDetail)
	}
	if _, errDetail := services.VerifyMFAEnrollment(ctx, testDB, signup.UserID, "000000"); errDetail == nil {
		t.Error("expected an incorrect enrollment code to be rejected")
	}
}

func TestMFA_DisableMFA_WrongPasswordRejected(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signup := signUpTestUser(t, ctx, email, "mfawrongpass", "correct horse battery staple")
	enrollAndVerifyMFA(t, ctx, signup.UserID, signup.Username)

	if errDetail := services.DisableMFA(ctx, testDB, signup.UserID, "the wrong password entirely"); errDetail == nil {
		t.Error("expected DisableMFA to require the correct current password")
	}
}

// TestMFA_Login_CorrectPasswordAloneIsNotEnough is the core integration
// point between login and MFA: a correct password alone must not be enough
// for an MFA-enabled account. See TestMFA_VerifyLogin_TOTPCode for
// completing the flow.
func TestMFA_Login_CorrectPasswordAloneIsNotEnough(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"
	signup := signUpTestUser(t, ctx, email, "mfaloginflow", password)
	enrollAndVerifyMFA(t, ctx, signup.UserID, signup.Username)

	login, errDetail := services.Login(ctx, testDB, testRedis, email, password)
	if errDetail != nil {
		t.Fatalf("Login: %+v", errDetail)
	}
	if !login.MFARequired {
		t.Fatal("expected MFARequired=true for an MFA-enabled account")
	}
	if login.AccessToken != "" || login.RefreshToken != "" {
		t.Error("expected no tokens to be issued before the MFA challenge is completed")
	}
	if login.MFAChallengeToken == "" {
		t.Fatal("expected a non-empty MFA challenge token")
	}
}

// TestMFA_VerifyLogin_TOTPCode exercises the full login -> MFA challenge ->
// verify-with-TOTP-code path with the secret kept in hand throughout, since
// Login itself never re-exposes it (by design — it's already encrypted at
// rest after enrollment).
func TestMFA_VerifyLogin_TOTPCode(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"
	signup := signUpTestUser(t, ctx, email, "mfaverifytotp", password)

	enrolled, errDetail := services.EnrollMFA(ctx, testDB, signup.UserID, signup.Username)
	if errDetail != nil {
		t.Fatalf("EnrollMFA: %+v", errDetail)
	}
	enrollCode, err := totp.GenerateCode(enrolled.Secret, time.Now())
	if err != nil {
		t.Fatalf("totp.GenerateCode: %v", err)
	}
	if _, errDetail := services.VerifyMFAEnrollment(ctx, testDB, signup.UserID, enrollCode); errDetail != nil {
		t.Fatalf("VerifyMFAEnrollment: %+v", errDetail)
	}

	login, errDetail := services.Login(ctx, testDB, testRedis, email, password)
	if errDetail != nil {
		t.Fatalf("Login: %+v", errDetail)
	}
	if !login.MFARequired {
		t.Fatal("expected MFARequired=true")
	}

	// A fresh code is needed here: the enrollment code above already
	// consumed that time-step (anti-replay), and depending on timing it may
	// still be the same 30s window.
	loginCode, err := totp.GenerateCode(enrolled.Secret, time.Now().Add(31*time.Second))
	if err != nil {
		t.Fatalf("totp.GenerateCode: %v", err)
	}

	result, errDetail := services.VerifyMFALogin(ctx, testDB, testRedis, login.MFAChallengeToken, "", loginCode)
	if errDetail != nil {
		t.Fatalf("VerifyMFALogin: %+v", errDetail)
	}
	if result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatal("expected real tokens after a successful MFA challenge")
	}
	if result.UserID != signup.UserID {
		t.Errorf("UserID = %q, want %q", result.UserID, signup.UserID)
	}

	if _, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+result.AccessToken); err != nil {
		t.Errorf("resulting access token doesn't verify: %v", err)
	}

	// The challenge token must be single-use.
	if _, errDetail := services.VerifyMFALogin(ctx, testDB, testRedis, login.MFAChallengeToken, "", loginCode); errDetail == nil {
		t.Error("expected a consumed MFA challenge token to be rejected on reuse")
	}
}

func TestMFA_VerifyLogin_RecoveryCode(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"
	signup := signUpTestUser(t, ctx, email, "mfarecoverycode", password)
	recoveryCodes := enrollAndVerifyMFA(t, ctx, signup.UserID, signup.Username)

	login, errDetail := services.Login(ctx, testDB, testRedis, email, password)
	if errDetail != nil {
		t.Fatalf("Login: %+v", errDetail)
	}

	result, errDetail := services.VerifyMFALogin(ctx, testDB, testRedis, login.MFAChallengeToken, "", recoveryCodes[0])
	if errDetail != nil {
		t.Fatalf("VerifyMFALogin with recovery code: %+v", errDetail)
	}
	if result.AccessToken == "" {
		t.Fatal("expected a real access token after a valid recovery code")
	}

	// Recovery codes are single-use — a second login attempt must not be
	// able to reuse the same one, even against a fresh challenge.
	login2, errDetail := services.Login(ctx, testDB, testRedis, email, password)
	if errDetail != nil {
		t.Fatalf("second Login: %+v", errDetail)
	}
	if _, errDetail := services.VerifyMFALogin(ctx, testDB, testRedis, login2.MFAChallengeToken, "", recoveryCodes[0]); errDetail == nil {
		t.Error("expected an already-used recovery code to be rejected")
	}

	// A different, still-unused recovery code must still work.
	if _, errDetail := services.VerifyMFALogin(ctx, testDB, testRedis, login2.MFAChallengeToken, "", recoveryCodes[1]); errDetail != nil {
		t.Errorf("expected a different unused recovery code to succeed: %+v", errDetail)
	}
}

func TestMFA_VerifyLogin_WrongCodeRejected(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"
	signup := signUpTestUser(t, ctx, email, "mfawronglogincode", password)
	enrollAndVerifyMFA(t, ctx, signup.UserID, signup.Username)

	login, errDetail := services.Login(ctx, testDB, testRedis, email, password)
	if errDetail != nil {
		t.Fatalf("Login: %+v", errDetail)
	}
	if _, errDetail := services.VerifyMFALogin(ctx, testDB, testRedis, login.MFAChallengeToken, "", "000000"); errDetail == nil {
		t.Error("expected an incorrect MFA code to be rejected")
	}
}

func TestMFA_VerifyLogin_ExpiredOrUnknownChallengeRejected(t *testing.T) {
	ctx := context.Background()
	if _, errDetail := services.VerifyMFALogin(ctx, testDB, testRedis, "not-a-real-challenge-token", "", "123456"); errDetail == nil {
		t.Error("expected a bogus challenge token to be rejected")
	}
}
