package integration

import (
	"context"
	"net/http"
	"testing"

	"auth-api/internal/auth"
	"auth-api/internal/services"
)

// enrollAndVerifyEmailMFA drives a full enroll->verify cycle for email MFA
// and returns the recovery codes issued on success.
func enrollAndVerifyEmailMFA(t *testing.T, ctx context.Context, userID string) []string {
	t.Helper()

	fakeResend, _ := newFakeResendClient(t, http.StatusOK)
	if errDetail := services.EnrollEmailMFA(ctx, testDB, testRedis, fakeResend, userID); errDetail != nil {
		t.Fatalf("EnrollEmailMFA: %+v", errDetail)
	}

	meta, err := auth.GetMFAOTPCode(ctx, testRedis, "email", "enroll", userID)
	if err != nil {
		t.Fatalf("GetMFAOTPCode: %v", err)
	}

	verified, errDetail := services.VerifyEmailMFAEnrollment(ctx, testDB, testRedis, userID, meta.Code)
	if errDetail != nil {
		t.Fatalf("VerifyEmailMFAEnrollment: %+v", errDetail)
	}
	if len(verified.RecoveryCodes) != 10 {
		t.Fatalf("got %d recovery codes, want 10 (config.Loaded.MFARecoveryCodeCount)", len(verified.RecoveryCodes))
	}
	return verified.RecoveryCodes
}

func TestMFAEmail_EnrollVerifyDisable_Lifecycle(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signup := signUpTestUser(t, ctx, email, "mfaemaillifecycle", "correct horse battery staple")

	enrollAndVerifyEmailMFA(t, ctx, signup.UserID)

	fakeResend, _ := newFakeResendClient(t, http.StatusOK)
	if errDetail := services.EnrollEmailMFA(ctx, testDB, testRedis, fakeResend, signup.UserID); errDetail == nil {
		t.Error("expected EnrollEmailMFA to reject enrollment when email MFA is already enabled")
	}

	if errDetail := services.DisableEmailMFA(ctx, testDB, signup.UserID, "correct horse battery staple"); errDetail != nil {
		t.Fatalf("DisableEmailMFA: %+v", errDetail)
	}
	if errDetail := services.DisableEmailMFA(ctx, testDB, signup.UserID, "correct horse battery staple"); errDetail == nil {
		t.Error("expected DisableEmailMFA to fail cleanly when nothing is enabled")
	}

	// A fresh enrollment after disabling must work (not conflict with the
	// deleted row).
	enrollAndVerifyEmailMFA(t, ctx, signup.UserID)
}

func TestMFAEmail_WrongCodeRejected(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signup := signUpTestUser(t, ctx, email, "mfaemailwrongcode", "correct horse battery staple")

	fakeResend, _ := newFakeResendClient(t, http.StatusOK)
	if errDetail := services.EnrollEmailMFA(ctx, testDB, testRedis, fakeResend, signup.UserID); errDetail != nil {
		t.Fatalf("EnrollEmailMFA: %+v", errDetail)
	}

	if _, errDetail := services.VerifyEmailMFAEnrollment(ctx, testDB, testRedis, signup.UserID, "000000"); errDetail == nil {
		t.Error("expected an incorrect code to be rejected")
	}
}

func TestMFAEmail_ResendCooldown(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signup := signUpTestUser(t, ctx, email, "mfaemailcooldown", "correct horse battery staple")

	fakeResend, callCount := newFakeResendClient(t, http.StatusOK)
	if errDetail := services.EnrollEmailMFA(ctx, testDB, testRedis, fakeResend, signup.UserID); errDetail != nil {
		t.Fatalf("EnrollEmailMFA: %+v", errDetail)
	}
	if errDetail := services.EnrollEmailMFA(ctx, testDB, testRedis, fakeResend, signup.UserID); errDetail == nil {
		t.Error("expected an immediate re-enrollment request to be rejected by the cooldown")
	}
	if callCount.Load() != 1 {
		t.Errorf("expected exactly one email send, got %d", callCount.Load())
	}
}

func TestMFAEmail_Login_FullFlow(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"
	signup := signUpTestUser(t, ctx, email, "mfaemaillogin", password)
	recoveryCodes := enrollAndVerifyEmailMFA(t, ctx, signup.UserID)

	login, errDetail := services.Login(ctx, testDB, testRedis, email, password)
	if errDetail != nil {
		t.Fatalf("Login: %+v", errDetail)
	}
	if !login.MFARequired {
		t.Fatal("expected MFARequired for an email-MFA-enabled account")
	}
	if len(login.MFAMethods) != 1 || login.MFAMethods[0] != "email" {
		t.Errorf("MFAMethods = %v, want [email]", login.MFAMethods)
	}

	fakeResend, _ := newFakeResendClient(t, http.StatusOK)
	if errDetail := services.SendMFALoginCode(ctx, testDB, testRedis, fakeResend, login.MFAChallengeToken, ""); errDetail != nil {
		t.Fatalf("SendMFALoginCode: %+v", errDetail)
	}

	meta, err := auth.GetMFAOTPCode(ctx, testRedis, "email", "login", signup.UserID)
	if err != nil {
		t.Fatalf("GetMFAOTPCode: %v", err)
	}

	// A wrong code first must not consume/invalidate the real one.
	if _, errDetail := services.VerifyMFALogin(ctx, testDB, testRedis, login.MFAChallengeToken, "", "000000"); errDetail == nil {
		t.Error("expected a wrong code to be rejected")
	}

	final, errDetail := services.VerifyMFALogin(ctx, testDB, testRedis, login.MFAChallengeToken, "email", meta.Code)
	if errDetail != nil {
		t.Fatalf("VerifyMFALogin: %+v", errDetail)
	}
	if final.AccessToken == "" || final.RefreshToken == "" {
		t.Fatal("expected real tokens after a successful email MFA login")
	}

	// The code is single-use — replaying it must fail even before its TTL
	// would naturally expire.
	if _, errDetail := services.VerifyMFALogin(ctx, testDB, testRedis, login.MFAChallengeToken, "email", meta.Code); errDetail == nil {
		t.Error("expected the same email code to be rejected on replay")
	}

	// A recovery code from enrollment still works as a fallback for email
	// MFA, exactly like it does for TOTP — mfa_recovery_codes rows aren't
	// filtered by factor type. It works even when a (wrong) method is
	// requested explicitly, since the recovery-code check isn't gated by
	// the requested method.
	login2, errDetail := services.Login(ctx, testDB, testRedis, email, password)
	if errDetail != nil {
		t.Fatalf("second Login: %+v", errDetail)
	}
	recoveryResult, errDetail := services.VerifyMFALogin(ctx, testDB, testRedis, login2.MFAChallengeToken, "email", recoveryCodes[0])
	if errDetail != nil {
		t.Fatalf("VerifyMFALogin via recovery code: %+v", errDetail)
	}
	if recoveryResult.AccessToken == "" {
		t.Fatal("expected real tokens after a successful recovery-code login")
	}
}

func TestMFAEmail_SendLoginCode_RejectedForTOTPChallenge(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"
	signup := signUpTestUser(t, ctx, email, "mfatotpsendcode", password)
	enrollAndVerifyMFA(t, ctx, signup.UserID, signup.Username)

	login, errDetail := services.Login(ctx, testDB, testRedis, email, password)
	if errDetail != nil {
		t.Fatalf("Login: %+v", errDetail)
	}
	if len(login.MFAMethods) != 1 || login.MFAMethods[0] != "totp" {
		t.Fatalf("MFAMethods = %v, want [totp]", login.MFAMethods)
	}

	fakeResend, callCount := newFakeResendClient(t, http.StatusOK)
	if errDetail := services.SendMFALoginCode(ctx, testDB, testRedis, fakeResend, login.MFAChallengeToken, ""); errDetail == nil {
		t.Error("expected SendMFALoginCode to be rejected for a TOTP-only challenge")
	}
	if callCount.Load() != 0 {
		t.Error("expected no email to be sent for a TOTP challenge")
	}
}

// TestMFAEmail_RequestSpecificMethod covers a client explicitly asking for
// one of several enabled methods, rather than accepting this codebase's
// default TOTP-first priority: requesting an unset-up method is rejected
// outright, and requesting a real one scopes verification to only that
// method's code.
func TestMFAEmail_RequestSpecificMethod(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"
	signup := signUpTestUser(t, ctx, email, "mfamethodpicker", password)
	enrollAndVerifyMFA(t, ctx, signup.UserID, signup.Username)
	enrollAndVerifyEmailMFA(t, ctx, signup.UserID)

	login, errDetail := services.Login(ctx, testDB, testRedis, email, password)
	if errDetail != nil {
		t.Fatalf("Login: %+v", errDetail)
	}
	if len(login.MFAMethods) != 2 || login.MFAMethods[0] != "totp" || login.MFAMethods[1] != "email" {
		t.Fatalf("MFAMethods = %v, want [totp email]", login.MFAMethods)
	}

	// Requesting a method that isn't set up at all must be rejected, not
	// silently fall back to something else.
	fakeResend, callCount := newFakeResendClient(t, http.StatusOK)
	if errDetail := services.SendMFALoginCode(ctx, testDB, testRedis, fakeResend, login.MFAChallengeToken, "sms"); errDetail == nil {
		t.Error("expected requesting an unconfigured method to be rejected")
	}
	if callCount.Load() != 0 {
		t.Error("expected no email to be sent for a rejected method request")
	}
	if _, errDetail := services.VerifyMFALogin(ctx, testDB, testRedis, login.MFAChallengeToken, "sms", "000000"); errDetail == nil {
		t.Error("expected verifying against an unconfigured method to be rejected")
	}

	// Explicitly requesting email (the non-default method — TOTP is
	// first in priority) must actually deliver and accept an email code,
	// even though the account also has TOTP enabled.
	if errDetail := services.SendMFALoginCode(ctx, testDB, testRedis, fakeResend, login.MFAChallengeToken, "email"); errDetail != nil {
		t.Fatalf("SendMFALoginCode(email): %+v", errDetail)
	}
	meta, err := auth.GetMFAOTPCode(ctx, testRedis, "email", "login", signup.UserID)
	if err != nil {
		t.Fatalf("GetMFAOTPCode: %v", err)
	}
	result, errDetail := services.VerifyMFALogin(ctx, testDB, testRedis, login.MFAChallengeToken, "email", meta.Code)
	if errDetail != nil {
		t.Fatalf("VerifyMFALogin(email): %+v", errDetail)
	}
	if result.AccessToken == "" {
		t.Fatal("expected real tokens after explicitly choosing email over the default TOTP method")
	}
}
