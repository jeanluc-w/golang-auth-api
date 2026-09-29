package auth

import (
	"context"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestWebAuthnRegistrationSession_RoundTrip(t *testing.T) {
	ctx := context.Background()
	rdb := newTestRedis(t)

	want := &webauthn.SessionData{
		Challenge: "reg-challenge-abc",
		UserID:    []byte{1, 2, 3, 4},
		Expires:   time.Now().Add(5 * time.Minute).Truncate(time.Second),
	}

	if err := SaveWebAuthnRegistrationSession(ctx, rdb, "user-1", want); err != nil {
		t.Fatalf("SaveWebAuthnRegistrationSession: %v", err)
	}

	got, err := GetWebAuthnRegistrationSession(ctx, rdb, "user-1")
	if err != nil {
		t.Fatalf("GetWebAuthnRegistrationSession: %v", err)
	}
	if got.Challenge != want.Challenge {
		t.Errorf("Challenge = %q, want %q", got.Challenge, want.Challenge)
	}
	if string(got.UserID) != string(want.UserID) {
		t.Errorf("UserID = %v, want %v", got.UserID, want.UserID)
	}
	if !got.Expires.Equal(want.Expires) {
		t.Errorf("Expires = %v, want %v", got.Expires, want.Expires)
	}

	if err := DeleteWebAuthnRegistrationSession(ctx, rdb, "user-1"); err != nil {
		t.Fatalf("DeleteWebAuthnRegistrationSession: %v", err)
	}
	if _, err := GetWebAuthnRegistrationSession(ctx, rdb, "user-1"); err == nil {
		t.Error("expected an error reading a deleted registration session")
	}
}

func TestWebAuthnLoginSession_RoundTrip(t *testing.T) {
	ctx := context.Background()
	rdb := newTestRedis(t)

	want := &webauthn.SessionData{
		Challenge: "login-challenge-xyz",
		Expires:   time.Now().Add(5 * time.Minute).Truncate(time.Second),
	}

	if err := SaveWebAuthnLoginSession(ctx, rdb, "ceremony-1", want); err != nil {
		t.Fatalf("SaveWebAuthnLoginSession: %v", err)
	}

	got, err := GetWebAuthnLoginSession(ctx, rdb, "ceremony-1")
	if err != nil {
		t.Fatalf("GetWebAuthnLoginSession: %v", err)
	}
	if got.Challenge != want.Challenge {
		t.Errorf("Challenge = %q, want %q", got.Challenge, want.Challenge)
	}

	if err := DeleteWebAuthnLoginSession(ctx, rdb, "ceremony-1"); err != nil {
		t.Fatalf("DeleteWebAuthnLoginSession: %v", err)
	}
	if _, err := GetWebAuthnLoginSession(ctx, rdb, "ceremony-1"); err == nil {
		t.Error("expected an error reading a deleted login session")
	}
}

// TestWebAuthnSession_RegistrationAndLoginDoNotCollide guards the reason
// registration is scoped by user ID and login by a random ceremony ID
// instead of sharing one key space: a user with a registration in flight
// (e.g. adding a second passkey) and an unrelated in-flight login ceremony
// must never read or clobber each other's session data, even if a
// ceremony ID happened to equal a user ID.
func TestWebAuthnSession_RegistrationAndLoginDoNotCollide(t *testing.T) {
	ctx := context.Background()
	rdb := newTestRedis(t)

	const sharedID = "user-1"
	reg := &webauthn.SessionData{Challenge: "reg-challenge", Expires: time.Now().Add(time.Minute)}
	login := &webauthn.SessionData{Challenge: "login-challenge", Expires: time.Now().Add(time.Minute)}

	if err := SaveWebAuthnRegistrationSession(ctx, rdb, sharedID, reg); err != nil {
		t.Fatalf("SaveWebAuthnRegistrationSession: %v", err)
	}
	if err := SaveWebAuthnLoginSession(ctx, rdb, sharedID, login); err != nil {
		t.Fatalf("SaveWebAuthnLoginSession: %v", err)
	}

	gotReg, err := GetWebAuthnRegistrationSession(ctx, rdb, sharedID)
	if err != nil || gotReg.Challenge != "reg-challenge" {
		t.Errorf("registration session = %+v, err=%v; want challenge 'reg-challenge'", gotReg, err)
	}
	gotLogin, err := GetWebAuthnLoginSession(ctx, rdb, sharedID)
	if err != nil || gotLogin.Challenge != "login-challenge" {
		t.Errorf("login session = %+v, err=%v; want challenge 'login-challenge'", gotLogin, err)
	}
}

func TestWebAuthnSession_MissingKey(t *testing.T) {
	ctx := context.Background()
	rdb := newTestRedis(t)

	if _, err := GetWebAuthnRegistrationSession(ctx, rdb, "never-started"); err == nil {
		t.Error("expected an error for a missing registration session")
	}
	if _, err := GetWebAuthnLoginSession(ctx, rdb, "never-started"); err == nil {
		t.Error("expected an error for a missing login session")
	}
}
