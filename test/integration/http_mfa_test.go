// HTTP-layer coverage for the email-MFA endpoints and the MFA
// method-selection feature (mfa_email_test.go already covers the
// service-layer behavior in depth). What's missing without this file is
// proof that the actual HTTP wiring — JSON body decoding on
// mfa/email/enroll, mfa/email/verify, mfa/send-login-code, and
// mfa/verify-login, including the optional "method" field — round-trips
// correctly through the real router and middleware stack.
package integration

import (
	"context"
	"net/http"
	"testing"

	"auth-api/internal/auth"
)

func TestHTTP_MFA_EmailEnrollVerifyDisableLifecycle(t *testing.T) {
	ts := newTestServer(t)
	token, _, _, userID := loginHTTPUser(t, ts)

	enrollResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/mfa/email/enroll", "Bearer "+token, nil)
	if enrollResp.Status != http.StatusOK {
		t.Fatalf("enroll: status = %d, body = %s", enrollResp.Status, enrollResp.Raw)
	}

	meta, err := auth.GetMFAOTPCode(context.Background(), testRedis, "email", "enroll", userID)
	if err != nil {
		t.Fatalf("GetMFAOTPCode: %v", err)
	}

	verifyResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/mfa/email/verify", "Bearer "+token, map[string]string{"code": meta.Code})
	if verifyResp.Status != http.StatusOK {
		t.Fatalf("verify: status = %d, body = %s", verifyResp.Status, verifyResp.Raw)
	}
	if _, ok := verifyResp.Body["recovery_codes"]; !ok {
		t.Errorf("verify response missing recovery_codes: %s", verifyResp.Raw)
	}

	disableResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/mfa/email/disable", "Bearer "+token, map[string]string{"current_password": "correct horse battery staple"})
	if disableResp.Status != http.StatusOK {
		t.Fatalf("disable: status = %d, body = %s", disableResp.Status, disableResp.Raw)
	}
}

func TestHTTP_MFA_EmailEnroll_RequiresAuth(t *testing.T) {
	ts := newTestServer(t)

	resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/mfa/email/enroll", "", nil)
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s, want 401", resp.Status, resp.Raw)
	}
}

// TestHTTP_MFA_LoginReportsMethodsAndRequestedMethodIsHonored drives the
// full method-selection flow over real HTTP: an account with both TOTP and
// email MFA enabled reports both methods on login, and explicitly
// requesting "email" (not the default-priority "totp") on
// mfa/send-login-code and mfa/verify-login actually completes the login
// via the email code rather than requiring a TOTP one.
func TestHTTP_MFA_LoginReportsMethodsAndRequestedMethodIsHonored(t *testing.T) {
	ctx := context.Background()
	ts := newTestServer(t)
	email := uniqueEmail(t)
	const password = "correct horse battery staple"

	signup := signUpTestUser(t, ctx, email, "httpmfamethod", password)
	enrollAndVerifyMFA(t, ctx, signup.UserID, signup.Username)
	enrollAndVerifyEmailMFA(t, ctx, signup.UserID)

	loginResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/login", "", map[string]string{"email": email, "password": password})
	if loginResp.Status != http.StatusOK {
		t.Fatalf("login: status = %d, body = %s", loginResp.Status, loginResp.Raw)
	}
	if loginResp.Body["mfa_required"] != true {
		t.Fatalf("expected mfa_required=true, got %s", loginResp.Raw)
	}
	methods, _ := loginResp.Body["methods"].([]any)
	if len(methods) != 2 || methods[0] != "totp" || methods[1] != "email" {
		t.Fatalf("methods = %v, want [totp email]", methods)
	}
	challengeToken, _ := loginResp.Body["challenge_token"].(string)
	if challengeToken == "" {
		t.Fatalf("missing challenge_token: %s", loginResp.Raw)
	}

	// Requesting an unconfigured method is rejected outright.
	badSendResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/mfa/send-login-code", "", map[string]string{
		"challenge_token": challengeToken, "method": "sms",
	})
	if badSendResp.Status != http.StatusBadRequest {
		t.Errorf("send-login-code(sms): status = %d, body = %s, want 400", badSendResp.Status, badSendResp.Raw)
	}

	sendResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/mfa/send-login-code", "", map[string]string{
		"challenge_token": challengeToken, "method": "email",
	})
	if sendResp.Status != http.StatusOK {
		t.Fatalf("send-login-code(email): status = %d, body = %s", sendResp.Status, sendResp.Raw)
	}

	meta, err := auth.GetMFAOTPCode(ctx, testRedis, "email", "login", signup.UserID)
	if err != nil {
		t.Fatalf("GetMFAOTPCode: %v", err)
	}

	verifyResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/mfa/verify-login", "", map[string]string{
		"challenge_token": challengeToken, "method": "email", "code": meta.Code,
	})
	if verifyResp.Status != http.StatusOK {
		t.Fatalf("verify-login: status = %d, body = %s", verifyResp.Status, verifyResp.Raw)
	}
	if verifyResp.Body["token"] == nil || verifyResp.Body["token"] == "" {
		t.Errorf("expected real tokens after completing login via the explicitly-requested email method: %s", verifyResp.Raw)
	}
}
