package auth

import (
	"encoding/base64"
	"testing"
)

func TestHashRefreshToken_Deterministic(t *testing.T) {
	a := HashRefreshToken("some-token-value")
	b := HashRefreshToken("some-token-value")
	if a != b {
		t.Errorf("expected deterministic hash, got %q and %q", a, b)
	}
}

func TestHashRefreshToken_DifferentInputsDifferentHashes(t *testing.T) {
	a := HashRefreshToken("token-one")
	b := HashRefreshToken("token-two")
	if a == b {
		t.Error("expected different inputs to produce different hashes")
	}
}

func TestHashRefreshToken_IsBase64URLNoPadding(t *testing.T) {
	got := HashRefreshToken("anything")
	if _, err := base64.RawURLEncoding.DecodeString(got); err != nil {
		t.Errorf("HashRefreshToken output isn't raw base64url: %v", err)
	}
}

func testPepper(n byte) string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = n
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestNewStaticPepperManager_Valid(t *testing.T) {
	raw := "id1:" + testPepper(1) + ",id2:" + testPepper(2)
	pm, err := NewStaticPepperManager(raw, "id2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pm.ActiveID() != "id2" {
		t.Errorf("ActiveID() = %q, want id2", pm.ActiveID())
	}
	if _, ok := pm.GetPepper("id1"); !ok {
		t.Error("expected id1 to be present")
	}
	active, err := pm.ActivePepper()
	if err != nil {
		t.Fatalf("ActivePepper() error: %v", err)
	}
	if len(active) != 16 {
		t.Errorf("active pepper length = %d, want 16", len(active))
	}
	if len(pm.All()) != 2 {
		t.Errorf("All() returned %d peppers, want 2", len(pm.All()))
	}
}

func TestNewStaticPepperManager_Errors(t *testing.T) {
	valid := "id1:" + testPepper(1)

	cases := map[string]struct {
		raw, active string
	}{
		"missing raw":           {"", "id1"},
		"missing active":        {valid, ""},
		"malformed entry":       {"id1-no-colon-value", "id1"},
		"pepper too short":      {"id1:" + base64.StdEncoding.EncodeToString([]byte("short")), "id1"},
		"active id not present": {valid, "does-not-exist"},
		"bad base64":            {"id1:not-valid-base64!!!", "id1"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewStaticPepperManager(c.raw, c.active); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestHashPasswordPHC_VerifyPasswordPHC_RoundTrip(t *testing.T) {
	setTestConfig(t, "active:"+testPepper(9), "active")

	const password = "correct horse battery staple"
	phc, err := HashPasswordPHC(password)
	if err != nil {
		t.Fatalf("HashPasswordPHC: %v", err)
	}

	ok, err := VerifyPasswordPHC(password, phc, false)
	if err != nil {
		t.Fatalf("VerifyPasswordPHC: %v", err)
	}
	if !ok {
		t.Error("expected correct password to verify")
	}

	ok, err = VerifyPasswordPHC("wrong password entirely", phc, false)
	if err != nil {
		t.Fatalf("VerifyPasswordPHC: %v", err)
	}
	if ok {
		t.Error("expected wrong password to fail verification")
	}
}

func TestHashPasswordPHC_RejectsInvalidPassword(t *testing.T) {
	setTestConfig(t, "active:"+testPepper(9), "active")

	if _, err := HashPasswordPHC("too short"); err == nil {
		t.Error("expected error for password below minimum length")
	}
}

func TestVerifyPasswordPHC_RotatedOutPepper(t *testing.T) {
	const password = "correct horse battery staple"
	peppers := "old:" + testPepper(1) + ",active:" + testPepper(2)

	// Hash while "old" is active, simulating a hash created before a pepper
	// rotation.
	setTestConfig(t, peppers, "old")
	phcUnderOld, err := HashPasswordPHC(password)
	if err != nil {
		t.Fatalf("HashPasswordPHC: %v", err)
	}

	// Simulate the rotation: "active" is now active, but "old" is still
	// configured — exactly so already-issued hashes keep working until
	// they're naturally rehashed on next login.
	setTestConfig(t, peppers, "active")

	ok, err := VerifyPasswordPHC(password, phcUnderOld, false)
	if err != nil {
		t.Fatalf("VerifyPasswordPHC: %v", err)
	}
	if !ok {
		t.Error("expected password hashed under a rotated-out-but-still-configured pepper to verify")
	}

	if should, err := ShouldRehashActive(phcUnderOld); err != nil {
		t.Fatalf("ShouldRehashActive: %v", err)
	} else if !should {
		t.Error("expected ShouldRehashActive to flag a hash using a non-active pepper")
	}
}

func TestVerifyPasswordPHC_TryAllIfMissing(t *testing.T) {
	const password = "correct horse battery staple"

	setTestConfig(t, "active:"+testPepper(3), "active")
	phc, err := HashPasswordPHC(password)
	if err != nil {
		t.Fatalf("HashPasswordPHC: %v", err)
	}

	// New config: the same pepper VALUE is present, but under a different
	// id than the PHC string references, and the original id is gone
	// entirely — simulates a pepper being renamed/fully retired.
	setTestConfig(t, "renamed:"+testPepper(3), "renamed")

	ok, err := VerifyPasswordPHC(password, phc, false)
	if err != nil {
		t.Fatalf("VerifyPasswordPHC: %v", err)
	}
	if ok {
		t.Error("expected verification to fail without tryAllIfMissing once the referenced pepper id is gone")
	}

	ok, err = VerifyPasswordPHC(password, phc, true)
	if err != nil {
		t.Fatalf("VerifyPasswordPHC: %v", err)
	}
	if !ok {
		t.Error("expected tryAllIfMissing to find the pepper by value even though its id changed")
	}
}

func TestShouldRehash(t *testing.T) {
	pm, err := NewStaticPepperManager("active:"+testPepper(1), "active")
	if err != nil {
		t.Fatalf("NewStaticPepperManager: %v", err)
	}

	current := "$argon2id$v=19$m=131072,t=2,p=4,pepper=active$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if ShouldRehash(current, pm) {
		t.Error("expected up-to-date hash to not need rehashing")
	}

	staleParams := "$argon2id$v=19$m=65536,t=1,p=4,pepper=active$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if !ShouldRehash(staleParams, pm) {
		t.Error("expected stale argon2 params to need rehashing")
	}

	stalePepper := "$argon2id$v=19$m=131072,t=2,p=4,pepper=retired$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if !ShouldRehash(stalePepper, pm) {
		t.Error("expected non-active pepper id to need rehashing")
	}

	if !ShouldRehash("not-a-valid-phc-string", pm) {
		t.Error("expected malformed PHC to need rehashing")
	}
}
