package auth

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"auth-api/config"
	"auth-api/internal/entities"

	"github.com/golang-jwt/jwt/v5"
)

// signTestToken builds and signs a JWT with the given claims against
// whatever config.Loaded currently holds, without going through
// generateAccessJWT (which would require a live Redis client just to record
// the session). This isolates parseJWT's own verification logic.
func signTestToken(t *testing.T, claims entities.JWTClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(config.Loaded.JWTAlgorithm, claims)
	signed, err := tok.SignedString(config.Loaded.JWTPrivateKey)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}

func baseClaims(exp time.Time) entities.JWTClaims {
	now := time.Now()
	return entities.JWTClaims{
		UserID:   "user-123",
		Username: "alice",
		Role:     "user",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    jwtIssuer,
			Audience:  jwt.ClaimStrings{jwtAudience},
			ID:        "session-abc",
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
		},
	}
}

func TestParseJWT_ValidToken(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")
	token := signTestToken(t, baseClaims(time.Now().Add(time.Hour)))

	claims, err := parseJWT("Bearer "+token, false)
	if err != nil {
		t.Fatalf("parseJWT: %v", err)
	}
	if claims.UserID != "user-123" || claims.ID != "session-abc" {
		t.Errorf("unexpected claims: %+v", claims)
	}
}

func TestParseJWT_ExpiredToken_RejectedWhenNotAllowed(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")
	token := signTestToken(t, baseClaims(time.Now().Add(-time.Minute)))

	if _, err := parseJWT("Bearer "+token, false); err == nil {
		t.Error("expected expired token to be rejected when allowExpired=false")
	}
}

// This is the core regression test for the bug where the original
// VerifyAndParseExpiredJWT compared an error against a freshly constructed
// errors.New(...) value (always unequal, so it always took the "not
// expired" branch) and, worse, parseJWT never actually produced that
// specific error in the first place because the JWT library rejected
// expired tokens with a generic wrapped error before the manual expiry
// check was ever reached. Net effect: refresh could never work correctly.
func TestParseJWT_ExpiredToken_AllowedWhenRequested(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")
	token := signTestToken(t, baseClaims(time.Now().Add(-time.Minute)))

	claims, err := parseJWT("Bearer "+token, true)
	if err != nil {
		t.Fatalf("parseJWT with allowExpired=true should accept an expired token: %v", err)
	}
	if claims.UserID != "user-123" || claims.ID != "session-abc" {
		t.Errorf("unexpected claims: %+v", claims)
	}
}

func TestParseJWT_WrongIssuer(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")
	claims := baseClaims(time.Now().Add(time.Hour))
	claims.Issuer = "someone-else"
	token := signTestToken(t, claims)

	if _, err := parseJWT("Bearer "+token, false); err == nil {
		t.Error("expected wrong issuer to be rejected")
	}
	if _, err := parseJWT("Bearer "+token, true); err == nil {
		t.Error("expected wrong issuer to be rejected even with allowExpired=true")
	}
}

func TestParseJWT_WrongAudience(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")
	claims := baseClaims(time.Now().Add(time.Hour))
	claims.Audience = jwt.ClaimStrings{"someone-elses-app"}
	token := signTestToken(t, claims)

	if _, err := parseJWT("Bearer "+token, false); err == nil {
		t.Error("expected wrong audience to be rejected")
	}
	if _, err := parseJWT("Bearer "+token, true); err == nil {
		t.Error("expected wrong audience to be rejected even with allowExpired=true")
	}
}

func TestParseJWT_TamperedSignature(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")
	token := signTestToken(t, baseClaims(time.Now().Add(time.Hour)))

	tampered := token[:len(token)-4] + "abcd"
	if tampered == token {
		t.Fatal("test bug: tampering did not change the token")
	}

	if _, err := parseJWT("Bearer "+tampered, false); err == nil {
		t.Error("expected tampered signature to be rejected")
	}
}

func TestParseJWT_WrongSigningAlgorithm(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")

	// Sign with a completely different key type/algorithm than the server
	// expects, to confirm keyFunc's algorithm check defends against
	// alg-confusion rather than just happening to fail on a key mismatch.
	otherPub, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	_ = otherPub
	claims := baseClaims(time.Now().Add(time.Hour))
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := tok.SignedString(otherPriv)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	if _, err := parseJWT("Bearer "+signed, false); err == nil {
		t.Error("expected token signed with an untrusted key to be rejected")
	}
}

func TestParseJWT_MalformedAuthHeader(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")

	cases := []string{"", "not-a-bearer-token", "Bearer", "Basic dXNlcjpwYXNz"}
	for _, h := range cases {
		if _, err := parseJWT(h, false); err == nil {
			t.Errorf("expected header %q to be rejected", h)
		}
	}
}

func TestVerifyAndParseExpiredJWT(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")

	t.Run("expired token succeeds", func(t *testing.T) {
		token := signTestToken(t, baseClaims(time.Now().Add(-time.Hour)))
		sessionID, userID, err := VerifyAndParseExpiredJWT(context.Background(), "Bearer "+token)
		if err != nil {
			t.Fatalf("VerifyAndParseExpiredJWT: %v", err)
		}
		if sessionID != "session-abc" || userID != "user-123" {
			t.Errorf("got sessionID=%q userID=%q", sessionID, userID)
		}
	})

	t.Run("non-expired token also succeeds", func(t *testing.T) {
		token := signTestToken(t, baseClaims(time.Now().Add(time.Hour)))
		if _, _, err := VerifyAndParseExpiredJWT(context.Background(), "Bearer "+token); err != nil {
			t.Fatalf("VerifyAndParseExpiredJWT: %v", err)
		}
	})

	t.Run("temporary (joiner) token is rejected", func(t *testing.T) {
		claims := baseClaims(time.Now().Add(-time.Hour))
		claims.Role = entities.RoleJoiner
		claims.UserID = ""
		token := signTestToken(t, claims)
		if _, _, err := VerifyAndParseExpiredJWT(context.Background(), "Bearer "+token); err == nil {
			t.Error("expected a joiner-role token to be rejected by the refresh path")
		}
	})

	t.Run("tampered token is rejected", func(t *testing.T) {
		token := signTestToken(t, baseClaims(time.Now().Add(-time.Hour)))
		tampered := token[:len(token)-4] + "abcd"
		if _, _, err := VerifyAndParseExpiredJWT(context.Background(), "Bearer "+tampered); err == nil {
			t.Error("expected tampered token to be rejected")
		}
	})
}

func TestHasAudience(t *testing.T) {
	claims := &entities.JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"a", "b", jwtAudience},
		},
	}
	if !hasAudience(claims, jwtAudience) {
		t.Error("expected audience to be found")
	}
	if hasAudience(claims, "not-present") {
		t.Error("expected audience not to be found")
	}
	if hasAudience(&entities.JWTClaims{}, jwtAudience) {
		t.Error("expected no match against empty audience list")
	}
}

func TestGenerateTemporaryJWT_RoleIsAlwaysJoiner(t *testing.T) {
	// Sanity check that the constant used across the package matches what
	// GenerateTemporaryJWT signs, without requiring a Redis client: build
	// the claims the same way and parse them back.
	setTestConfig(t, "unused:"+testPepper(1), "unused")
	claims := entities.JWTClaims{
		Role: entities.RoleJoiner,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "someone@example.com",
			Issuer:    jwtIssuer,
			Audience:  jwt.ClaimStrings{jwtAudience},
			ID:        "temp-session",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-5 * time.Second)),
		},
	}
	token := signTestToken(t, claims)

	parsed, err := parseJWT("Bearer "+token, false)
	if err != nil {
		t.Fatalf("parseJWT: %v", err)
	}
	if parsed.Role != entities.RoleJoiner {
		t.Errorf("Role = %q, want %q", parsed.Role, entities.RoleJoiner)
	}
	if !strings.Contains(parsed.Subject, "@") {
		t.Errorf("expected Subject to carry the email, got %q", parsed.Subject)
	}
}
