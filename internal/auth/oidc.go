package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// Well-known OIDC issuer/JWKS endpoints for the two SSO providers this
// service supports. These are fixed, public, provider-owned values — not
// configuration — only the audience (config.Loaded.GoogleClientID /
// AppleClientID) varies per deployment.
const (
	GoogleIssuer  = "https://accounts.google.com"
	GoogleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"
	AppleIssuer   = "https://appleid.apple.com"
	AppleJWKSURL  = "https://appleid.apple.com/auth/keys"
)

// NewProviderKeyfunc fetches and caches (with automatic background refresh
// on the provider's normal key-rotation schedule) the JWKS at jwksURL,
// returning a keyfunc.Keyfunc ready to verify that provider's ID tokens.
// Build one of these once per provider at startup (it does a live HTTP
// fetch) and reuse it for every request — never construct one per request.
func NewProviderKeyfunc(ctx context.Context, jwksURL string) (keyfunc.Keyfunc, error) {
	return keyfunc.NewDefaultCtx(ctx, []string{jwksURL})
}

// OIDCClaims are the subset of ID token claims this service relies on for
// SSO login/signup.
type OIDCClaims struct {
	Subject       string // "sub" — the provider's stable, opaque user identifier
	Email         string
	EmailVerified bool
}

// oidcRawClaims mirrors the wire claims needed to populate OIDCClaims.
// EmailVerified is deliberately json.RawMessage: Google sends it as a JSON
// boolean, but Apple sends it as a JSON STRING ("true"/"false") — a
// well-documented quirk of Apple's identity tokens. Decoding straight into
// bool would fail outright on Apple's tokens.
type oidcRawClaims struct {
	jwt.RegisteredClaims
	Email         string          `json:"email"`
	EmailVerified json.RawMessage `json:"email_verified"`
}

func (c *oidcRawClaims) emailVerifiedBool() bool {
	if len(c.EmailVerified) == 0 {
		return false
	}
	var asBool bool
	if err := json.Unmarshal(c.EmailVerified, &asBool); err == nil {
		return asBool
	}
	var asString string
	if err := json.Unmarshal(c.EmailVerified, &asString); err == nil {
		return asString == "true"
	}
	return false
}

// VerifyOIDCToken verifies idToken's signature against kf's JWKS and its
// issuer/audience/expiry against wantIssuer/wantAudience, returning the
// claims this service needs on success. kf must already be constructed
// (NewProviderKeyfunc) — this function does no network I/O itself, which is
// also what makes it testable against a fake JWKS server.
func VerifyOIDCToken(idToken string, kf keyfunc.Keyfunc, wantIssuer, wantAudience string) (*OIDCClaims, error) {
	claims := &oidcRawClaims{}
	token, err := jwt.ParseWithClaims(idToken, claims, kf.Keyfunc,
		jwt.WithIssuer(wantIssuer),
		jwt.WithAudience(wantAudience),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid OIDC token: %w", err)
	}
	if claims.Subject == "" {
		return nil, errors.New("OIDC token missing subject claim")
	}
	return &OIDCClaims{
		Subject:       claims.Subject,
		Email:         claims.Email,
		EmailVerified: claims.emailVerifiedBool(),
	}, nil
}
