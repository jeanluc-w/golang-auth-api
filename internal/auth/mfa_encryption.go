package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"auth-api/config"
)

// EncryptMFASecret encrypts a TOTP secret for storage using AES-256-GCM
// with config.Loaded.MFAEncryptionKey, returning a single string (a random
// nonce prepended to the ciphertext, base64url-encoded) suitable for the
// mfa_factors.secret column.
//
// Unlike a password, a TOTP secret can't be hashed at rest — verifying a
// code requires the plaintext secret back, not just a comparison — so it's
// encrypted instead, using a key that itself is never stored in the
// database (config.Loaded.MFAEncryptionKey, same principle as password
// peppers): a stolen DB dump alone must not be enough to generate valid
// codes for every enrolled account.
func EncryptMFASecret(plaintext string) (string, error) {
	gcm, err := mfaGCM()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// DecryptMFASecret reverses EncryptMFASecret.
func DecryptMFASecret(encoded string) (string, error) {
	gcm, err := mfaGCM()
	if err != nil {
		return "", err
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decoding ciphertext: %w", err)
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}
	return string(plaintext), nil
}

func mfaGCM() (cipher.AEAD, error) {
	block, err := aes.NewCipher(config.Loaded.MFAEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	return gcm, nil
}
