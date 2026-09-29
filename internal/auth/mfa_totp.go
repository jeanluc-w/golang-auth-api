package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	totpPeriod = 30 // seconds; matches every mainstream authenticator app's default
	totpSkew   = 1  // allow ±1 step (±30s) of clock drift between server and device
	totpDigits = otp.DigitsSix
)

// GenerateTOTPSecret creates a new random TOTP secret and its
// provisioning URI (otpauth://...), which a client renders as a QR code (or
// shows for manual entry) in an authenticator app. The raw secret returned
// here must be encrypted (EncryptMFASecret) before it's persisted.
func GenerateTOTPSecret(issuer, accountName string) (secret string, provisioningURI string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      totpPeriod,
		Digits:      totpDigits,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// totpStep returns the time-step index t falls into for the standard
// 30-second period.
func totpStep(t time.Time) int64 {
	return t.Unix() / totpPeriod
}

// ValidateTOTPCode checks code against secret, allowing ±totpSkew steps of
// clock drift. lastUsedStep is the last step this factor successfully
// authenticated with (0 if never); any step at or before it is rejected
// even if the code would otherwise be valid — TOTP's ~30-60s validity
// window alone doesn't prevent a captured code from being replayed within
// it. On success, matchedStep is what the caller must persist as the new
// lastUsedStep.
func ValidateTOTPCode(secret, code string, lastUsedStep int64, now time.Time) (matchedStep int64, ok bool) {
	opts := totp.ValidateOpts{
		Period: totpPeriod,
		Digits: totpDigits,
	}
	current := totpStep(now)
	for skew := -int64(totpSkew); skew <= int64(totpSkew); skew++ {
		step := current + skew
		if step <= lastUsedStep {
			continue
		}
		candidate, err := totp.GenerateCodeCustom(secret, time.Unix(step*totpPeriod, 0), opts)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// GenerateMFARecoveryCode returns a random, human-typeable, single-use
// recovery code (80 bits of entropy, base32, grouped for readability) for
// when a user's authenticator device is unavailable. Only its hash
// (HashOpaqueToken) is ever persisted — see db/queries/mfa.sql.
func GenerateMFARecoveryCode() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)

	var groups []string
	for i := 0; i < len(encoded); i += 4 {
		end := min(i+4, len(encoded))
		groups = append(groups, encoded[i:end])
	}
	return strings.Join(groups, "-"), nil
}
