package auth

import (
	"crypto/ed25519"
	"sync"
	"testing"

	"auth-api/config"

	"github.com/golang-jwt/jwt/v5"
)

// setTestConfig installs a fresh config.Loaded for the duration of a test.
//
// It also resets the package-level pepper-manager cache (see
// ActivePepperManager in hash.go): that cache is a sync.Once keyed to the
// process lifetime, which is the right call in production (peppers never
// change without a restart) but means tests that need to exercise more than
// one pepper configuration in the same test binary must explicitly clear it
// between setups, or they'll silently keep verifying against a previous
// test's config.
func setTestConfig(t *testing.T, peppersRaw, activePepperID string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	config.Loaded = &config.Config{
		Env:                "test",
		PasswordPeppersRaw: peppersRaw,
		ActivePepperID:     activePepperID,
		JWTPrivateKey:      priv,
		JWTPublicKey:       pub,
		JWTAlgorithm:       jwt.SigningMethodEdDSA,
	}
	activePepperManagerOnce = sync.Once{}
	activePepperManagerVal = nil
	activePepperManagerErr = nil
}
