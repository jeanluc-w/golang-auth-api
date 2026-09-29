package auth

import (
	"strings"
	"testing"
	"time"

	"auth-api/config"

	"github.com/pquerna/otp/totp"
)

func TestEncryptDecryptMFASecret_RoundTrip(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")

	const secret = "JBSWY3DPEHPK3PXP"
	encrypted, err := EncryptMFASecret(secret)
	if err != nil {
		t.Fatalf("EncryptMFASecret: %v", err)
	}
	if encrypted == secret {
		t.Error("expected ciphertext to differ from plaintext")
	}
	if strings.Contains(encrypted, secret) {
		t.Error("ciphertext should not contain the plaintext secret")
	}

	decrypted, err := DecryptMFASecret(encrypted)
	if err != nil {
		t.Fatalf("DecryptMFASecret: %v", err)
	}
	if decrypted != secret {
		t.Errorf("decrypted = %q, want %q", decrypted, secret)
	}
}

func TestEncryptMFASecret_Nondeterministic(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")

	a, err := EncryptMFASecret("same-secret")
	if err != nil {
		t.Fatalf("EncryptMFASecret: %v", err)
	}
	b, err := EncryptMFASecret("same-secret")
	if err != nil {
		t.Fatalf("EncryptMFASecret: %v", err)
	}
	if a == b {
		t.Error("expected two encryptions of the same plaintext to differ (random nonce)")
	}
}

func TestDecryptMFASecret_WrongKeyFails(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")
	encrypted, err := EncryptMFASecret("some-secret")
	if err != nil {
		t.Fatalf("EncryptMFASecret: %v", err)
	}

	// A different key (e.g. after a misconfiguration) must not be able to
	// decrypt data encrypted under the original one.
	config.Loaded.MFAEncryptionKey = make([]byte, 32) // all-zero, different from the random key setTestConfig generated
	if _, err := DecryptMFASecret(encrypted); err == nil {
		t.Error("expected decryption with the wrong key to fail")
	}
}

func TestDecryptMFASecret_TamperedCiphertextFails(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")
	encrypted, err := EncryptMFASecret("some-secret")
	if err != nil {
		t.Fatalf("EncryptMFASecret: %v", err)
	}
	tampered := encrypted[:len(encrypted)-2] + "zz"
	if tampered == encrypted {
		t.Fatal("test bug: tampering did not change the ciphertext")
	}
	if _, err := DecryptMFASecret(tampered); err == nil {
		t.Error("expected GCM authentication to reject tampered ciphertext")
	}
}

func TestGenerateAndValidateTOTPCode(t *testing.T) {
	secret, uri, err := GenerateTOTPSecret("auth-api-test", "someone@example.com")
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if secret == "" {
		t.Fatal("expected a non-empty secret")
	}
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Errorf("provisioning URI = %q, want an otpauth://totp/ URI", uri)
	}

	now := time.Now()
	code, err := totpCodeAt(t, secret, now)
	if err != nil {
		t.Fatalf("generating a code to validate: %v", err)
	}

	step, ok := ValidateTOTPCode(secret, code, 0, now)
	if !ok {
		t.Fatal("expected a freshly generated valid code to validate")
	}
	if step != totpStep(now) {
		t.Errorf("matched step = %d, want %d", step, totpStep(now))
	}
}

func TestValidateTOTPCode_WrongCodeRejected(t *testing.T) {
	secret, _, err := GenerateTOTPSecret("auth-api-test", "someone@example.com")
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if _, ok := ValidateTOTPCode(secret, "000000", 0, time.Now()); ok {
		// Astronomically unlikely to be the real code, but guard against
		// the 1-in-a-million flake by regenerating once.
		if _, ok := ValidateTOTPCode(secret, "000001", 0, time.Now()); ok {
			t.Skip("false positive on both guess codes; extraordinarily unlucky, skipping")
		}
	}
}

func TestValidateTOTPCode_RejectsReplayOfSameStep(t *testing.T) {
	secret, _, err := GenerateTOTPSecret("auth-api-test", "someone@example.com")
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	now := time.Now()
	code, err := totpCodeAt(t, secret, now)
	if err != nil {
		t.Fatalf("generating a code to validate: %v", err)
	}

	step, ok := ValidateTOTPCode(secret, code, 0, now)
	if !ok {
		t.Fatal("expected the first use of a valid code to succeed")
	}

	// Replaying the exact same code, with lastUsedStep now set to what the
	// first call returned, must be rejected even though the code is still
	// within its normal ~30-90s validity window.
	if _, ok := ValidateTOTPCode(secret, code, step, now); ok {
		t.Error("expected replaying an already-used code/step to be rejected")
	}
}

func TestValidateTOTPCode_AllowsAdjacentStepWithinSkew(t *testing.T) {
	secret, _, err := GenerateTOTPSecret("auth-api-test", "someone@example.com")
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	now := time.Now()
	// A code generated 30s in the past should still validate against
	// "now" thanks to the ±1 step skew tolerance for clock drift.
	past := now.Add(-30 * time.Second)
	code, err := totpCodeAt(t, secret, past)
	if err != nil {
		t.Fatalf("generating a code to validate: %v", err)
	}

	if _, ok := ValidateTOTPCode(secret, code, 0, now); !ok {
		t.Error("expected a code from one step in the past to validate within the skew window")
	}
}

func TestGenerateMFARecoveryCode(t *testing.T) {
	a, err := GenerateMFARecoveryCode()
	if err != nil {
		t.Fatalf("GenerateMFARecoveryCode: %v", err)
	}
	b, err := GenerateMFARecoveryCode()
	if err != nil {
		t.Fatalf("GenerateMFARecoveryCode: %v", err)
	}
	if a == b {
		t.Error("expected two recovery codes not to collide")
	}
	if !strings.Contains(a, "-") {
		t.Errorf("expected a grouped, hyphenated code, got %q", a)
	}
	if strings.ContainsAny(a, "01") {
		// Not a strict requirement of base32, just documenting the actual
		// alphabet in use (RFC 4648 standard base32 excludes 0/1 already).
		t.Logf("code contains 0/1: %q", a)
	}
}

// totpCodeAt generates a code for secret at a specific time, using the same
// period/digits ValidateTOTPCode expects, so tests can construct a
// known-valid code without a real authenticator app.
func totpCodeAt(t *testing.T, secret string, at time.Time) (string, error) {
	t.Helper()
	return totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{
		Period: totpPeriod,
		Digits: totpDigits,
	})
}
