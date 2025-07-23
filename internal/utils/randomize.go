package utils

import (
	"math/rand"
)

// GenerateVerificationCode creates a random 6-digit code
func GenerateCode() string {
	const digits = "0123456789"
	code := make([]byte, 6)
	for i := range code {
		code[i] = digits[rand.Intn(len(digits))]
	}
	return string(code)
}
