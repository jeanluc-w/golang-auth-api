package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// GenerateCode creates a cryptographically random 6-digit verification code
// (000000-999999, zero-padded). It uses crypto/rand rather than math/rand
// since these codes gate account verification and must not be guessable.
func GenerateCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		// crypto/rand failure means the OS CSPRNG is broken; there is no
		// safe fallback for a security-sensitive code, so fail loudly.
		panic(fmt.Sprintf("utils: crypto/rand unavailable: %v", err))
	}
	return fmt.Sprintf("%06d", n.Int64())
}
