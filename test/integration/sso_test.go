package integration

import (
	"context"
	"testing"

	"auth-api/internal/auth"
	"auth-api/internal/db/postgres"
	"auth-api/internal/services"
)

// SSOLogin takes already-verified claims (auth.OIDCClaims) rather than a
// raw ID token — token signature/issuer/audience verification itself is
// unit-tested in detail against a fake JWKS server in
// internal/auth/oidc_test.go, with no need for Postgres/Redis. These tests
// cover what IS DB-dependent: the account-linking/conflict/creation policy
// documented on services.SSOLogin.

func TestSSOLogin_NewAccount_CreatedAndUsable(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	claims := &auth.OIDCClaims{Subject: "google-sub-" + email, Email: email, EmailVerified: true}

	result, errDetail := services.SSOLogin(ctx, testDB, testRedis, postgres.ProviderNameGoogle, postgres.UserOriginGoogle, claims)
	if errDetail != nil {
		t.Fatalf("SSOLogin: %+v", errDetail)
	}
	if result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatal("expected real tokens for a brand-new SSO account")
	}
	if result.Username == "" {
		t.Error("expected an auto-generated username")
	}

	if _, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+result.AccessToken); err != nil {
		t.Errorf("resulting access token doesn't verify: %v", err)
	}
}

func TestSSOLogin_ExistingIdentity_LogsIn(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	claims := &auth.OIDCClaims{Subject: "google-sub-" + email, Email: email, EmailVerified: true}

	first, errDetail := services.SSOLogin(ctx, testDB, testRedis, postgres.ProviderNameGoogle, postgres.UserOriginGoogle, claims)
	if errDetail != nil {
		t.Fatalf("first SSOLogin: %+v", errDetail)
	}

	second, errDetail := services.SSOLogin(ctx, testDB, testRedis, postgres.ProviderNameGoogle, postgres.UserOriginGoogle, claims)
	if errDetail != nil {
		t.Fatalf("second SSOLogin: %+v", errDetail)
	}
	if second.UserID != first.UserID {
		t.Errorf("second login user ID = %q, want the same account (%q) — should not create a duplicate", second.UserID, first.UserID)
	}
	if second.Username != first.Username {
		t.Errorf("username changed between logins: %q vs %q", first.Username, second.Username)
	}
}

func TestSSOLogin_EmailNotVerified_Rejected(t *testing.T) {
	ctx := context.Background()
	claims := &auth.OIDCClaims{Subject: "google-sub-unverified", Email: uniqueEmail(t), EmailVerified: false}

	if _, errDetail := services.SSOLogin(ctx, testDB, testRedis, postgres.ProviderNameGoogle, postgres.UserOriginGoogle, claims); errDetail == nil {
		t.Error("expected an unverified provider email to be rejected")
	}
}

// TestSSOLogin_EmailConflict_Rejected locks in the conservative
// account-linking policy: an SSO login for an email that already has an
// account (via password signup here, but the same applies to a different
// SSO provider) is rejected rather than silently linked — see
// services.SSOLogin's doc comment for why.
func TestSSOLogin_EmailConflict_Rejected(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signUpTestUser(t, ctx, email, "ssoconflictuser", "correct horse battery staple")

	claims := &auth.OIDCClaims{Subject: "google-sub-conflict", Email: email, EmailVerified: true}
	if _, errDetail := services.SSOLogin(ctx, testDB, testRedis, postgres.ProviderNameGoogle, postgres.UserOriginGoogle, claims); errDetail == nil {
		t.Error("expected SSO login to be rejected when the email already has an account under a different identity")
	}
}

func TestSSOLogin_DifferentProvidersSameEmail_SecondIsConflict(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	googleClaims := &auth.OIDCClaims{Subject: "google-sub-" + email, Email: email, EmailVerified: true}
	if _, errDetail := services.SSOLogin(ctx, testDB, testRedis, postgres.ProviderNameGoogle, postgres.UserOriginGoogle, googleClaims); errDetail != nil {
		t.Fatalf("Google SSOLogin: %+v", errDetail)
	}

	// A DIFFERENT provider (Apple) presenting the SAME email is a conflict,
	// not an automatic account merge — even though both logins are for
	// "the same person" in reality, this service has no way to confirm
	// that beyond the email match, which is exactly the ambiguity the
	// conservative policy exists to avoid.
	appleClaims := &auth.OIDCClaims{Subject: "apple-sub-" + email, Email: email, EmailVerified: true}
	if _, errDetail := services.SSOLogin(ctx, testDB, testRedis, postgres.ProviderNameApple, postgres.UserOriginApple, appleClaims); errDetail == nil {
		t.Error("expected a second provider claiming the same email to be rejected as a conflict")
	}
}

func TestSSOLogin_UsernameCollision_GetsSuffixed(t *testing.T) {
	ctx := context.Background()
	localPart := "collideuser"

	first := &auth.OIDCClaims{Subject: "google-sub-1-" + localPart, Email: localPart + "@example.com", EmailVerified: true}
	firstResult, errDetail := services.SSOLogin(ctx, testDB, testRedis, postgres.ProviderNameGoogle, postgres.UserOriginGoogle, first)
	if errDetail != nil {
		t.Fatalf("first SSOLogin: %+v", errDetail)
	}

	// Same local part, different domain -> different email, so this is a
	// legitimately new account, but its naive username candidate collides
	// with the first one's.
	second := &auth.OIDCClaims{Subject: "google-sub-2-" + localPart, Email: localPart + "@another-example.com", EmailVerified: true}
	secondResult, errDetail := services.SSOLogin(ctx, testDB, testRedis, postgres.ProviderNameGoogle, postgres.UserOriginGoogle, second)
	if errDetail != nil {
		t.Fatalf("second SSOLogin: %+v", errDetail)
	}

	if firstResult.Username == secondResult.Username {
		t.Errorf("expected usernames to differ after a collision, both are %q", firstResult.Username)
	}
}
