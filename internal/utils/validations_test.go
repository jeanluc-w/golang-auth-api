package utils

import (
	"strings"
	"testing"
)

func TestIsValidEmail(t *testing.T) {
	cases := map[string]bool{
		"a@b.co":                         true,
		"first.last+tag@sub.example.com": true,
		"":                               false,
		"no-at-sign.com":                 false,
		"double@@at.com":                 false,
		"missing-domain@":                false,
		"@missing-local.com":             false,
		"trailing-dot@example.":          false,
		"has space@example.com":          false,
	}
	for in, want := range cases {
		if got := IsValidEmail(in); got != want {
			t.Errorf("IsValidEmail(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsValidUsername(t *testing.T) {
	cases := map[string]bool{
		"ab":                    true, // minimum length (2)
		"a":                     false,
		"":                      false,
		"valid_user.name":       true,
		".leadingdot":           false,
		"trailingdot.":          false,
		"_leadingunderscore":    false,
		"has space":             false,
		strings.Repeat("a", 30): true,  // max length
		strings.Repeat("a", 31): false, // over max length
	}
	for in, want := range cases {
		if got := IsValidUsername(in); got != want {
			t.Errorf("IsValidUsername(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsValidPassword(t *testing.T) {
	cases := map[string]bool{
		"":                       false,
		strings.Repeat("a", 11):  false, // below minimum
		strings.Repeat("a", 12):  true,  // at minimum
		strings.Repeat("a", 128): true,  // at maximum
		strings.Repeat("a", 129): false, // over maximum
		"correct horse battery":  true,
	}
	for in, want := range cases {
		if got := IsValidPassword(in); got != want {
			t.Errorf("IsValidPassword(len=%d) = %v, want %v", len(in), got, want)
		}
	}
}

func TestIsValidVerificationCode(t *testing.T) {
	cases := map[string]bool{
		"123456":  true,
		"000000":  true,
		"12345":   false, // too short
		"1234567": false, // too long
		"12345a":  false, // non-digit
		"":        false,
	}
	for in, want := range cases {
		if got := IsValidVerificationCode(in); got != want {
			t.Errorf("IsValidVerificationCode(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsOriginAllowed(t *testing.T) {
	whitelist := []string{"https://example.com", "https://app.example.com"}

	if !IsOriginAllowed("https://example.com", whitelist) {
		t.Error("expected exact match to be allowed")
	}
	if IsOriginAllowed("https://evil.com", whitelist) {
		t.Error("expected unlisted origin to be rejected")
	}
	if IsOriginAllowed("https://example.com.evil.com", whitelist) {
		t.Error("expected suffix-only match to be rejected (no substring matching)")
	}
	if IsOriginAllowed("", whitelist) {
		t.Error("expected empty origin to be rejected")
	}
	if IsOriginAllowed("https://example.com", nil) {
		t.Error("expected nil whitelist to allow nothing")
	}
}
