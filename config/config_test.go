package config

import (
	"bytes"
	"testing"
)

func TestParseListConfig(t *testing.T) {
	cases := []struct {
		name     string
		envValue string
		envSet   bool
		fallback string
		want     []string
	}{
		{"unset uses fallback", "", false, "", nil},
		{"unset with non-empty fallback", "", false, "a,b", []string{"a", "b"}},
		{"set explicitly empty still falls back", "", true, "x,y", []string{"x", "y"}},
		{"trims whitespace and drops empty entries", " a, b ,,c", true, "", []string{"a", "b", "c"}},
		{"single value", "https://example.com", true, "", []string{"https://example.com"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			const key = "TEST_PARSE_LIST_CONFIG"
			if c.envSet {
				t.Setenv(key, c.envValue)
			}
			got := parseListConfig(key, c.fallback)
			if !equalStringSlices(got, c.want) {
				t.Errorf("parseListConfig(%q, %q) = %#v, want %#v", c.envValue, c.fallback, got, c.want)
			}
		})
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestGetStringConfig(t *testing.T) {
	const key = "TEST_GET_STRING_CONFIG"

	if got := getStringConfig(key, "fallback"); got != "fallback" {
		t.Errorf("unset: got %q, want fallback", got)
	}

	t.Setenv(key, "actual-value")
	if got := getStringConfig(key, "fallback"); got != "actual-value" {
		t.Errorf("set: got %q, want actual-value", got)
	}
}

func TestRequireStringConfig_HappyPath(t *testing.T) {
	const key = "TEST_REQUIRE_STRING_CONFIG"
	t.Setenv(key, "present")
	if got := requireStringConfig(key); got != "present" {
		t.Errorf("got %q, want present", got)
	}
}

func TestParseIntConfig_HappyPath(t *testing.T) {
	const key = "TEST_PARSE_INT_CONFIG"

	if got := parseIntConfig(key, "42"); got != 42 {
		t.Errorf("fallback: got %d, want 42", got)
	}
	t.Setenv(key, "7")
	if got := parseIntConfig(key, "42"); got != 7 {
		t.Errorf("env set: got %d, want 7", got)
	}
}

func TestParseFloatConfig_HappyPath(t *testing.T) {
	const key = "TEST_PARSE_FLOAT_CONFIG"

	if got := parseFloatConfig(key, "1.5"); got != 1.5 {
		t.Errorf("fallback: got %v, want 1.5", got)
	}
	t.Setenv(key, "0.25")
	if got := parseFloatConfig(key, "1.5"); got != 0.25 {
		t.Errorf("env set: got %v, want 0.25", got)
	}
}

func TestLoadPrivateKey_PlainPKCS8(t *testing.T) {
	dir := t.TempDir()
	privFile, _, _, wantPriv := writeEd25519KeyPair(t, dir)

	got := loadPrivateKey(privFile)
	if !bytes.Equal(got, wantPriv) {
		t.Error("loaded private key does not match the generated key")
	}
}

func TestLoadPublicKey_PKIX(t *testing.T) {
	dir := t.TempDir()
	_, pubFile, wantPub, _ := writeEd25519KeyPair(t, dir)

	got := loadPublicKey(pubFile)
	if !bytes.Equal(got, wantPub) {
		t.Error("loaded public key does not match the generated key")
	}
}

func TestLoadPrivateKey_EncryptedPKCS8(t *testing.T) {
	dir := t.TempDir()
	_, _, _, wantPriv := writeEd25519KeyPair(t, dir)
	encFile := writeEncryptedPrivateKey(t, dir, wantPriv, "correct-horse-battery-staple")

	t.Setenv("JWT_PRIVATE_KEY_PASSPHRASE", "correct-horse-battery-staple")

	got := loadPrivateKey(encFile)
	if !bytes.Equal(got, wantPriv) {
		t.Error("decrypted private key does not match the original key")
	}
}

func TestLoad_HappyPath(t *testing.T) {
	dir := t.TempDir()
	privFile, pubFile, wantPub, wantPriv := writeEd25519KeyPair(t, dir)

	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
	t.Setenv("PASSWORD_PEPPERS", "id1:MDEyMzQ1Njc4OWFiY2RlZg==")
	t.Setenv("ACTIVE_PEPPER_ID", "id1")
	t.Setenv("SENTRY_DSN", "https://public@sentry.example.com/1")
	t.Setenv("REDIS_ADDR", "localhost:6379")
	t.Setenv("RESEND_API_KEY", "test-key")
	t.Setenv("JWT_PRIVATE_KEY_FILE", privFile)
	t.Setenv("JWT_PUBLIC_KEY_FILE", pubFile)
	// Everything else left unset to exercise the documented defaults.
	t.Cleanup(func() { Loaded = nil })

	Load()

	if Loaded == nil {
		t.Fatal("Loaded is nil after Load()")
	}
	if Loaded.Env != "development" {
		t.Errorf("Env = %q, want development (default)", Loaded.Env)
	}
	if Loaded.Port != "8080" {
		t.Errorf("Port = %q, want 8080 (default)", Loaded.Port)
	}
	if Loaded.DSN != "postgres://user:pass@localhost:5432/db" {
		t.Errorf("DSN = %q", Loaded.DSN)
	}
	if Loaded.RateLimit.Limit != 10 {
		t.Errorf("RateLimit.Limit = %d, want 10 (default)", Loaded.RateLimit.Limit)
	}
	if Loaded.EmailFromAddress != "auth <no-reply@mail.auth.com>" {
		t.Errorf("EmailFromAddress = %q, want the default", Loaded.EmailFromAddress)
	}
	if Loaded.AllowedOrigins != nil {
		t.Errorf("AllowedOrigins = %#v, want nil (unset)", Loaded.AllowedOrigins)
	}
	if Loaded.LoginMaxFailedAttempts != 5 {
		t.Errorf("LoginMaxFailedAttempts = %d, want 5 (default)", Loaded.LoginMaxFailedAttempts)
	}
	if !bytes.Equal(Loaded.JWTPrivateKey, wantPriv) {
		t.Error("JWTPrivateKey does not match the fixture key")
	}
	if !bytes.Equal(Loaded.JWTPublicKey, wantPub) {
		t.Error("JWTPublicKey does not match the fixture key")
	}
	if Loaded.JWTAlgorithm == nil {
		t.Error("JWTAlgorithm is nil")
	}
}

func TestLoad_HappyPath_OverridesRespected(t *testing.T) {
	dir := t.TempDir()
	privFile, pubFile, _, _ := writeEd25519KeyPair(t, dir)

	t.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")
	t.Setenv("PASSWORD_PEPPERS", "id1:MDEyMzQ1Njc4OWFiY2RlZg==")
	t.Setenv("ACTIVE_PEPPER_ID", "id1")
	t.Setenv("SENTRY_DSN", "https://public@sentry.example.com/1")
	t.Setenv("REDIS_ADDR", "localhost:6379")
	t.Setenv("RESEND_API_KEY", "test-key")
	t.Setenv("JWT_PRIVATE_KEY_FILE", privFile)
	t.Setenv("JWT_PUBLIC_KEY_FILE", pubFile)
	t.Setenv("ENV", "production")
	t.Setenv("PORT", "9090")
	t.Setenv("ALLOWED_ORIGINS", "https://a.example.com, https://b.example.com")
	t.Setenv("LOGIN_MAX_FAILED_ATTEMPTS", "3")
	t.Cleanup(func() { Loaded = nil })

	Load()

	if Loaded.Env != "production" {
		t.Errorf("Env = %q, want production", Loaded.Env)
	}
	if Loaded.Port != "9090" {
		t.Errorf("Port = %q, want 9090", Loaded.Port)
	}
	if !equalStringSlices(Loaded.AllowedOrigins, []string{"https://a.example.com", "https://b.example.com"}) {
		t.Errorf("AllowedOrigins = %#v", Loaded.AllowedOrigins)
	}
	if Loaded.LoginMaxFailedAttempts != 3 {
		t.Errorf("LoginMaxFailedAttempts = %d, want 3", Loaded.LoginMaxFailedAttempts)
	}
}
