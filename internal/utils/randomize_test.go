package utils

import (
	"regexp"
	"testing"
)

var sixDigits = regexp.MustCompile(`^\d{6}$`)

func TestGenerateCode_Format(t *testing.T) {
	for i := 0; i < 1000; i++ {
		code := GenerateCode()
		if !sixDigits.MatchString(code) {
			t.Fatalf("GenerateCode() = %q, want exactly 6 digits", code)
		}
	}
}

func TestGenerateCode_Varies(t *testing.T) {
	seen := make(map[string]bool, 200)
	for i := 0; i < 200; i++ {
		seen[GenerateCode()] = true
	}
	// With a 1,000,000-value space and 200 samples, collisions should be
	// rare; this is a smoke test against a broken/constant generator, not a
	// statistical randomness proof.
	if len(seen) < 190 {
		t.Fatalf("GenerateCode() produced only %d distinct values out of 200 calls; looks non-random", len(seen))
	}
}
