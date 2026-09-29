package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
)

// fakeOIDCProvider stands in for a real OIDC provider (Google/Apple) in
// tests: it serves a JWKS containing one RSA public key at a local
// httptest.Server, and can sign ID tokens with the matching private key.
// This is the same "redirect at a local server" trick used for Resend in
// the integration test suite — VerifyOIDCToken never talks to a real
// network endpoint in any test.
type fakeOIDCProvider struct {
	privateKey *rsa.PrivateKey
	kid        string
	server     *httptest.Server
}

func newFakeOIDCProvider(t *testing.T) *fakeOIDCProvider {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	const kid = "test-key-1"

	jwk, err := jwkset.NewJWKFromKey(priv.Public(), jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{
			KID: kid,
			ALG: jwkset.AlgRS256,
			USE: jwkset.UseSig,
		},
	})
	if err != nil {
		t.Fatalf("jwkset.NewJWKFromKey: %v", err)
	}
	jwksJSON, err := json.Marshal(jwkset.JWKSMarshal{Keys: []jwkset.JWKMarshal{jwk.Marshal()}})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	t.Cleanup(server.Close)

	return &fakeOIDCProvider{privateKey: priv, kid: kid, server: server}
}

// idToken signs a set of claims as this provider, in the raw wire shape
// (including Apple's email_verified-as-string quirk when asString is set)
// rather than going through entities.JWTClaims, since this is deliberately
// a DIFFERENT token shape/issuer than this service's own tokens.
func (p *fakeOIDCProvider) idToken(t *testing.T, subject, issuer, audience, email string, emailVerified any) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":            issuer,
		"aud":            audience,
		"sub":            subject,
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Unix(),
		"email":          email,
		"email_verified": emailVerified,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = p.kid
	signed, err := tok.SignedString(p.privateKey)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}

func TestVerifyOIDCToken_HappyPath_BoolEmailVerified(t *testing.T) {
	provider := newFakeOIDCProvider(t)
	kf, err := NewProviderKeyfunc(t.Context(), provider.server.URL)
	if err != nil {
		t.Fatalf("NewProviderKeyfunc: %v", err)
	}

	token := provider.idToken(t, "google-user-123", "https://accounts.google.com", "test-client-id", "someone@example.com", true)

	claims, err := VerifyOIDCToken(token, kf, "https://accounts.google.com", "test-client-id")
	if err != nil {
		t.Fatalf("VerifyOIDCToken: %v", err)
	}
	if claims.Subject != "google-user-123" {
		t.Errorf("Subject = %q, want google-user-123", claims.Subject)
	}
	if claims.Email != "someone@example.com" {
		t.Errorf("Email = %q", claims.Email)
	}
	if !claims.EmailVerified {
		t.Error("expected EmailVerified = true")
	}
}

// TestVerifyOIDCToken_StringEmailVerified locks in support for Apple's
// well-documented quirk of sending email_verified as the JSON string
// "true"/"false" rather than a JSON boolean.
func TestVerifyOIDCToken_StringEmailVerified(t *testing.T) {
	provider := newFakeOIDCProvider(t)
	kf, err := NewProviderKeyfunc(t.Context(), provider.server.URL)
	if err != nil {
		t.Fatalf("NewProviderKeyfunc: %v", err)
	}

	token := provider.idToken(t, "apple-user-456", "https://appleid.apple.com", "test-client-id", "someone@example.com", "true")

	claims, err := VerifyOIDCToken(token, kf, "https://appleid.apple.com", "test-client-id")
	if err != nil {
		t.Fatalf("VerifyOIDCToken: %v", err)
	}
	if !claims.EmailVerified {
		t.Error("expected EmailVerified = true from the string \"true\"")
	}

	falseToken := provider.idToken(t, "apple-user-456", "https://appleid.apple.com", "test-client-id", "someone@example.com", "false")
	claims, err = VerifyOIDCToken(falseToken, kf, "https://appleid.apple.com", "test-client-id")
	if err != nil {
		t.Fatalf("VerifyOIDCToken: %v", err)
	}
	if claims.EmailVerified {
		t.Error("expected EmailVerified = false from the string \"false\"")
	}
}

func TestVerifyOIDCToken_WrongAudienceRejected(t *testing.T) {
	provider := newFakeOIDCProvider(t)
	kf, err := NewProviderKeyfunc(t.Context(), provider.server.URL)
	if err != nil {
		t.Fatalf("NewProviderKeyfunc: %v", err)
	}
	token := provider.idToken(t, "user-1", "https://accounts.google.com", "someone-elses-client-id", "someone@example.com", true)

	if _, err := VerifyOIDCToken(token, kf, "https://accounts.google.com", "test-client-id"); err == nil {
		t.Error("expected a token issued for a different audience/client ID to be rejected")
	}
}

func TestVerifyOIDCToken_WrongIssuerRejected(t *testing.T) {
	provider := newFakeOIDCProvider(t)
	kf, err := NewProviderKeyfunc(t.Context(), provider.server.URL)
	if err != nil {
		t.Fatalf("NewProviderKeyfunc: %v", err)
	}
	token := provider.idToken(t, "user-1", "https://evil.example.com", "test-client-id", "someone@example.com", true)

	if _, err := VerifyOIDCToken(token, kf, "https://accounts.google.com", "test-client-id"); err == nil {
		t.Error("expected a token from an unexpected issuer to be rejected")
	}
}

func TestVerifyOIDCToken_ExpiredRejected(t *testing.T) {
	provider := newFakeOIDCProvider(t)
	kf, err := NewProviderKeyfunc(t.Context(), provider.server.URL)
	if err != nil {
		t.Fatalf("NewProviderKeyfunc: %v", err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://accounts.google.com", "aud": "test-client-id", "sub": "user-1",
		"exp": now.Add(-time.Hour).Unix(), "iat": now.Add(-2 * time.Hour).Unix(),
		"email": "someone@example.com", "email_verified": true,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = provider.kid
	signed, err := tok.SignedString(provider.privateKey)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	if _, err := VerifyOIDCToken(signed, kf, "https://accounts.google.com", "test-client-id"); err == nil {
		t.Error("expected an expired token to be rejected")
	}
}

func TestVerifyOIDCToken_TamperedSignatureRejected(t *testing.T) {
	provider := newFakeOIDCProvider(t)
	kf, err := NewProviderKeyfunc(t.Context(), provider.server.URL)
	if err != nil {
		t.Fatalf("NewProviderKeyfunc: %v", err)
	}
	token := provider.idToken(t, "user-1", "https://accounts.google.com", "test-client-id", "someone@example.com", true)
	tampered := token[:len(token)-4] + "abcd"
	if tampered == token {
		t.Fatal("test bug: tampering did not change the token")
	}

	if _, err := VerifyOIDCToken(tampered, kf, "https://accounts.google.com", "test-client-id"); err == nil {
		t.Error("expected a tampered signature to be rejected")
	}
}

func TestVerifyOIDCToken_UntrustedSigningKeyRejected(t *testing.T) {
	provider := newFakeOIDCProvider(t)
	kf, err := NewProviderKeyfunc(t.Context(), provider.server.URL)
	if err != nil {
		t.Fatalf("NewProviderKeyfunc: %v", err)
	}

	// Sign with a completely different key than the one published in the
	// provider's JWKS — simulates an attacker who controls neither Google
	// nor Apple's actual signing keys trying to forge a token.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	claims := jwt.MapClaims{
		"iss": "https://accounts.google.com", "aud": "test-client-id", "sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(), "email": "someone@example.com", "email_verified": true,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = provider.kid // claims the legitimate key ID, but signs with a different key
	signed, err := tok.SignedString(otherKey)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	if _, err := VerifyOIDCToken(signed, kf, "https://accounts.google.com", "test-client-id"); err == nil {
		t.Error("expected a token signed by an untrusted key to be rejected")
	}
}
