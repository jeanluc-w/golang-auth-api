package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"auth-api/internal/auth"
	"auth-api/internal/services"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// These tests deliberately do NOT simulate a full WebAuthn ceremony (a
// signed attestation/assertion from a virtual authenticator) — doing that
// correctly means reimplementing a meaningful slice of what
// github.com/go-webauthn/webauthn's own (much larger) test suite already
// covers: COSE key generation, CBOR attestation-object encoding, and
// authenticator-data signing that has to match the wire format byte for
// byte. That library is the thing being trusted for cryptographic ceremony
// correctness here, the same way pgx or go-redis are trusted rather than
// re-verified — see README's Security notes for the fuller reasoning.
//
// What IS tested here is this codebase's own glue around it: that
// Begin*'s Redis-backed session round-trips correctly, that Finish*
// rejects a missing/expired session before ever reaching the library, that
// passkey management (list/rename/delete) is correctly scoped to the
// owning user, and that every entry point degrades to PasskeyNotConfigured
// when WEBAUTHN_RP_ID isn't set — exactly the properties that would still
// need covering even with a real authenticator in the loop.

func testWebAuthn(t *testing.T) *webauthn.WebAuthn {
	t.Helper()
	w, err := webauthn.New(&webauthn.Config{
		RPID:          "example.com",
		RPDisplayName: "auth-api test",
		RPOrigins:     []string{"https://example.com"},
	})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	return w
}

// seedPasskey inserts a webauthn_credentials row directly, bypassing the
// real registration ceremony — valid for testing management operations
// (list/rename/delete), none of which unmarshal the credential JSON
// itself, only Begin*/Finish* do.
func seedPasskey(t *testing.T, ctx context.Context, userID, name string) (passkeyID string) {
	t.Helper()
	credID := uuid.New()
	row := testDB.QueryRow(ctx,
		`INSERT INTO webauthn_credentials (user_id, credential_id, name, credential) VALUES ($1, $2, $3, '{}'::jsonb) RETURNING id`,
		userUUID(t, userID), credID[:], name,
	)
	var id pgtype.UUID
	if err := row.Scan(&id); err != nil {
		t.Fatalf("seedPasskey insert: %v", err)
	}
	return id.String()
}

func TestPasskey_NotConfigured_AllOperationsRejected(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"
	signup := signUpTestUser(t, ctx, email, "passkeynotconfigured", password)

	if _, errDetail := services.BeginPasskeyRegistration(ctx, testDB, testRedis, nil, signup.UserID, signup.Username); errDetail == nil {
		t.Error("expected BeginPasskeyRegistration to reject when WebAuthn isn't configured")
	}
	if errDetail := services.FinishPasskeyRegistration(ctx, testDB, testRedis, nil, signup.UserID, signup.Username, "", httptest.NewRequest(http.MethodPost, "/", nil)); errDetail == nil {
		t.Error("expected FinishPasskeyRegistration to reject when WebAuthn isn't configured")
	}
	if _, errDetail := services.BeginPasskeyLogin(ctx, testRedis, nil); errDetail == nil {
		t.Error("expected BeginPasskeyLogin to reject when WebAuthn isn't configured")
	}
	if _, errDetail := services.FinishPasskeyLogin(ctx, testDB, testRedis, nil, "bogus", httptest.NewRequest(http.MethodPost, "/", nil)); errDetail == nil {
		t.Error("expected FinishPasskeyLogin to reject when WebAuthn isn't configured")
	}
}

func TestPasskey_BeginRegistration_StoresRedisSession(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signup := signUpTestUser(t, ctx, email, "passkeybeginreg", "correct horse battery staple")
	w := testWebAuthn(t)

	options, errDetail := services.BeginPasskeyRegistration(ctx, testDB, testRedis, w, signup.UserID, signup.Username)
	if errDetail != nil {
		t.Fatalf("BeginPasskeyRegistration: %+v", errDetail)
	}
	if options.Response.Challenge.String() == "" {
		t.Error("expected a non-empty registration challenge")
	}
	if options.Response.RelyingParty.ID != "example.com" {
		t.Errorf("RP ID = %q, want example.com", options.Response.RelyingParty.ID)
	}

	session, err := auth.GetWebAuthnRegistrationSession(ctx, testRedis, signup.UserID)
	if err != nil {
		t.Fatalf("GetWebAuthnRegistrationSession: %v", err)
	}
	if session.Challenge != options.Response.Challenge.String() {
		t.Error("stored session challenge doesn't match the one returned to the client")
	}
}

func TestPasskey_BeginLogin_StoresRedisSession(t *testing.T) {
	ctx := context.Background()
	w := testWebAuthn(t)

	challenge, errDetail := services.BeginPasskeyLogin(ctx, testRedis, w)
	if errDetail != nil {
		t.Fatalf("BeginPasskeyLogin: %+v", errDetail)
	}
	if challenge.CeremonyID == "" {
		t.Fatal("expected a non-empty ceremony ID")
	}

	session, err := auth.GetWebAuthnLoginSession(ctx, testRedis, challenge.CeremonyID)
	if err != nil {
		t.Fatalf("GetWebAuthnLoginSession: %v", err)
	}
	if session.Challenge != challenge.Options.Response.Challenge.String() {
		t.Error("stored session challenge doesn't match the one returned to the client")
	}
}

func TestPasskey_FinishRegistration_MissingSessionRejected(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signup := signUpTestUser(t, ctx, email, "passkeynosession", "correct horse battery staple")
	w := testWebAuthn(t)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if errDetail := services.FinishPasskeyRegistration(ctx, testDB, testRedis, w, signup.UserID, signup.Username, "", req); errDetail == nil {
		t.Error("expected FinishPasskeyRegistration to reject when no registration was ever begun")
	}
}

func TestPasskey_FinishLogin_UnknownCeremonyRejected(t *testing.T) {
	ctx := context.Background()
	w := testWebAuthn(t)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if _, errDetail := services.FinishPasskeyLogin(ctx, testDB, testRedis, w, "no-such-ceremony", req); errDetail == nil {
		t.Error("expected FinishPasskeyLogin to reject an unknown/expired ceremony ID")
	}
}

func TestPasskey_ManagementLifecycle(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"
	owner := signUpTestUser(t, ctx, email, "passkeymgmtowner", password)
	otherEmail := uniqueEmail(t)
	other := signUpTestUser(t, ctx, otherEmail, "passkeymgmtother", password)

	passkeyID := seedPasskey(t, ctx, owner.UserID, "Original Name")

	list, errDetail := services.ListPasskeys(ctx, testDB, owner.UserID)
	if errDetail != nil {
		t.Fatalf("ListPasskeys: %+v", errDetail)
	}
	if len(list) != 1 || list[0].ID != passkeyID || list[0].Name != "Original Name" {
		t.Fatalf("ListPasskeys = %+v, want one entry named 'Original Name' with id %s", list, passkeyID)
	}

	// Another user can't rename or delete it.
	if errDetail := services.RenamePasskey(ctx, testDB, other.UserID, passkeyID, "Hijacked"); errDetail == nil {
		t.Error("expected another user renaming this passkey to be rejected")
	}
	if errDetail := services.DeletePasskey(ctx, testDB, other.UserID, password, passkeyID); errDetail == nil {
		t.Error("expected another user deleting this passkey to be rejected")
	}

	if errDetail := services.RenamePasskey(ctx, testDB, owner.UserID, passkeyID, "Renamed"); errDetail != nil {
		t.Fatalf("RenamePasskey: %+v", errDetail)
	}
	list, errDetail = services.ListPasskeys(ctx, testDB, owner.UserID)
	if errDetail != nil {
		t.Fatalf("ListPasskeys after rename: %+v", errDetail)
	}
	if len(list) != 1 || list[0].Name != "Renamed" {
		t.Fatalf("ListPasskeys after rename = %+v, want name 'Renamed'", list)
	}

	if errDetail := services.DeletePasskey(ctx, testDB, owner.UserID, "the wrong password", passkeyID); errDetail == nil {
		t.Error("expected an incorrect password to be rejected on delete")
	}
	if errDetail := services.DeletePasskey(ctx, testDB, owner.UserID, password, passkeyID); errDetail != nil {
		t.Fatalf("DeletePasskey: %+v", errDetail)
	}
	list, errDetail = services.ListPasskeys(ctx, testDB, owner.UserID)
	if errDetail != nil {
		t.Fatalf("ListPasskeys after delete: %+v", errDetail)
	}
	if len(list) != 0 {
		t.Fatalf("ListPasskeys after delete = %+v, want empty", list)
	}
}
