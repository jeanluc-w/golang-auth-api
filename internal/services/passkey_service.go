package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"auth-api/internal/auth"
	"auth-api/internal/db/postgres"
	"auth-api/internal/utils"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Passkey (WebAuthn) registration/login ceremonies are the one place in
// this codebase where a service function takes *http.Request directly —
// every Finish*/Validate* call in github.com/go-webauthn/webauthn is built
// around parsing the raw request body itself (byte-exact, since it's what
// the client-reported signature actually covers); pre-parsing it into a
// DTO and reconstructing the bytes elsewhere risks a subtle mismatch in
// exactly the code path where that would be a security bug, not a cosmetic
// one. Everything else about these functions (DB access, Redis-backed
// ceremony state, error handling) follows this codebase's usual
// handler/service split.
//
// A successful passkey login bypasses the separate TOTP/email MFA gate
// entirely (it calls issueLoginSession directly, not Login) — a passkey is
// already phishing-resistant, device-bound, and typically backed by a
// platform biometric/PIN prompt, so it already satisfies what a second
// factor exists to add rather than needing one stacked on top.

// loadWebAuthnUser builds the webauthn.User adapter for userID from every
// credential currently on file, needed both to exclude already-registered
// authenticators from a fresh registration and to verify a login assertion
// against the right public key. Returns the raw DB rows too, since the
// caller (FinishPasskeyLogin) needs to map the credential the ceremony
// actually used back to its row id to write the post-login update.
func loadWebAuthnUser(ctx context.Context, q *postgres.Queries, userID pgtype.UUID, username string) (*auth.WebAuthnUser, []postgres.GetWebAuthnCredentialsByUserIDRow, error) {
	rows, err := q.GetWebAuthnCredentialsByUserID(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	creds := make([]webauthn.Credential, 0, len(rows))
	for _, row := range rows {
		var cred webauthn.Credential
		if err := json.Unmarshal(row.Credential, &cred); err != nil {
			return nil, nil, err
		}
		creds = append(creds, cred)
	}
	userIDBytes := userID.Bytes
	return &auth.WebAuthnUser{
		ID: userIDBytes[:], Username: username, DisplayName: username, Credentials: creds,
	}, rows, nil
}

// BeginPasskeyRegistration starts adding a passkey to an already
// authenticated account. Requested as a discoverable (resident) credential
// so it works with usernameless login later.
func BeginPasskeyRegistration(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, webAuthn *webauthn.WebAuthn, userID, username string) (*protocol.CredentialCreation, *utils.ErrorDetail) {
	if webAuthn == nil {
		return nil, &utils.Errors.PasskeyNotConfigured
	}
	userPG, ok := parseUserID(userID)
	if !ok {
		return nil, &utils.Errors.Unauthorized
	}
	q := postgres.New(db)

	waUser, _, err := loadWebAuthnUser(ctx, q, userPG, username)
	if err != nil {
		utils.LogError(ctx, "loadWebAuthnUser failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	exclusions := make([]protocol.CredentialDescriptor, 0, len(waUser.Credentials))
	for _, c := range waUser.Credentials {
		exclusions = append(exclusions, c.Descriptor())
	}

	creation, session, err := webAuthn.BeginRegistration(waUser,
		webauthn.WithExclusions(exclusions),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	)
	if err != nil {
		utils.LogError(ctx, "BeginRegistration failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	if err := auth.SaveWebAuthnRegistrationSession(ctx, redisClient, userID, session); err != nil {
		utils.LogError(ctx, "SaveWebAuthnRegistrationSession failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	return creation, nil
}

// FinishPasskeyRegistration completes registration: verifies the
// authenticator's response against the pending session, then persists the
// new credential. name is an optional user-facing label ("MacBook Touch
// ID"); it is never shown to, or trusted from, anyone but the owning user.
func FinishPasskeyRegistration(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, webAuthn *webauthn.WebAuthn, userID, username, name string, r *http.Request) *utils.ErrorDetail {
	if webAuthn == nil {
		return &utils.Errors.PasskeyNotConfigured
	}
	userPG, ok := parseUserID(userID)
	if !ok {
		return &utils.Errors.Unauthorized
	}
	q := postgres.New(db)

	session, err := auth.GetWebAuthnRegistrationSession(ctx, redisClient, userID)
	if err != nil {
		return &utils.Errors.InvalidOrExpiredToken
	}

	waUser, _, err := loadWebAuthnUser(ctx, q, userPG, username)
	if err != nil {
		utils.LogError(ctx, "loadWebAuthnUser failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	cred, err := webAuthn.FinishRegistration(waUser, *session, r)
	if err != nil {
		utils.LogDebug(ctx, "FinishRegistration failed", zap.Error(err))
		return &utils.Errors.PasskeyChallengeFailed
	}

	credJSON, err := json.Marshal(cred)
	if err != nil {
		utils.LogError(ctx, "marshal webauthn credential failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	if _, err := q.CreateWebAuthnCredential(ctx, postgres.CreateWebAuthnCredentialParams{
		UserID: userPG, CredentialID: cred.ID, Name: textOrNull(strings.TrimSpace(name)), Credential: credJSON,
	}); err != nil {
		if isUniqueViolation(err) {
			return &utils.Errors.PasskeyAlreadyRegistered
		}
		utils.LogError(ctx, "CreateWebAuthnCredential failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	if err := auth.DeleteWebAuthnRegistrationSession(ctx, redisClient, userID); err != nil {
		utils.LogWarn(ctx, "DeleteWebAuthnRegistrationSession failed", zap.Error(err))
	}

	// Self-service action: actor_id is left NULL, same as every other
	// self-driven audit entry in this codebase (contrast with
	// admin_service.go, which always attributes an actor).
	if err := q.CreateAuditLog(ctx, postgres.CreateAuditLogParams{
		TargetUserID: userPG, TargetUsername: textOrNull(username),
		Action: postgres.AuditActionMfaChange, Reason: textOrNull("Passkey registered"),
	}); err != nil {
		utils.LogWarn(ctx, "CreateAuditLog failed", zap.Error(err))
	}

	utils.LogInfo(ctx, "Passkey registered", zap.String("user_id", userID))
	return nil
}

// PasskeyLoginChallenge is BeginPasskeyLogin's response: ceremonyID must be
// round-tripped to FinishPasskeyLogin (there's no authenticated session yet
// to scope the pending ceremony to — see auth.SaveWebAuthnLoginSession).
type PasskeyLoginChallenge struct {
	CeremonyID string                        `json:"ceremony_id"`
	Options    *protocol.CredentialAssertion `json:"options"`
}

// BeginPasskeyLogin starts a usernameless (discoverable-credential) login:
// the authenticator itself supplies which account it belongs to when the
// user picks a passkey, so no email/username input is needed up front —
// and unlike password login, there's no enumeration surface to protect
// here in the first place.
func BeginPasskeyLogin(ctx context.Context, redisClient *redis.Client, webAuthn *webauthn.WebAuthn) (*PasskeyLoginChallenge, *utils.ErrorDetail) {
	if webAuthn == nil {
		return nil, &utils.Errors.PasskeyNotConfigured
	}

	assertion, session, err := webAuthn.BeginDiscoverableLogin()
	if err != nil {
		utils.LogError(ctx, "BeginDiscoverableLogin failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	ceremonyID, err := auth.RandomToken(32)
	if err != nil {
		utils.LogError(ctx, "RandomToken failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}
	if err := auth.SaveWebAuthnLoginSession(ctx, redisClient, ceremonyID, session); err != nil {
		utils.LogError(ctx, "SaveWebAuthnLoginSession failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	return &PasskeyLoginChallenge{CeremonyID: ceremonyID, Options: assertion}, nil
}

// FinishPasskeyLogin completes a passkey login: verifies the assertion
// against whichever account the authenticator identified (via its user
// handle — see auth.WebAuthnUser's doc comment), re-checks account status
// the same way every other login path does, persists the authenticator's
// updated sign-count, and issues a normal session — skipping the separate
// MFA gate; see this file's package doc for why.
func FinishPasskeyLogin(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, webAuthn *webauthn.WebAuthn, ceremonyID string, r *http.Request) (*LoginResult, *utils.ErrorDetail) {
	if webAuthn == nil {
		return nil, &utils.Errors.PasskeyNotConfigured
	}
	session, err := auth.GetWebAuthnLoginSession(ctx, redisClient, ceremonyID)
	if err != nil {
		return nil, &utils.Errors.InvalidOrExpiredToken
	}
	q := postgres.New(db)

	var resolvedUser postgres.GetUserForWebAuthnLoginRow
	var resolvedUserPG pgtype.UUID
	var resolvedRows []postgres.GetWebAuthnCredentialsByUserIDRow
	var lookupErr error

	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		if len(userHandle) != 16 {
			return nil, errors.New("unexpected webauthn user handle length")
		}
		var uid pgtype.UUID
		copy(uid.Bytes[:], userHandle)
		uid.Valid = true

		userRow, err := q.GetUserForWebAuthnLogin(ctx, uid)
		if err != nil {
			lookupErr = err
			return nil, err
		}
		waUser, rows, err := loadWebAuthnUser(ctx, q, uid, userRow.Username)
		if err != nil {
			lookupErr = err
			return nil, err
		}
		resolvedUser, resolvedUserPG, resolvedRows = userRow, uid, rows
		return waUser, nil
	}

	_, cred, err := webAuthn.FinishPasskeyLogin(handler, *session, r)
	if err != nil {
		if lookupErr != nil {
			utils.LogError(ctx, "webauthn login user lookup failed", zap.Error(lookupErr))
			return nil, &utils.Errors.InternalServerError
		}
		utils.LogDebug(ctx, "FinishPasskeyLogin failed", zap.Error(err))
		return nil, &utils.Errors.PasskeyChallengeFailed
	}

	// Re-check account status now that identity is proven — could have
	// changed since the credential was registered.
	if resolvedUser.DeletedAt.Valid || (resolvedUser.Status.Valid && (resolvedUser.Status.UserStatus == postgres.UserStatusBanned || resolvedUser.Status.UserStatus == postgres.UserStatusDisabled)) {
		return nil, &utils.Errors.AccountNotUsable
	}

	credJSON, err := json.Marshal(cred)
	if err != nil {
		utils.LogError(ctx, "marshal webauthn credential failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}
	for _, row := range resolvedRows {
		if bytes.Equal(row.CredentialID, cred.ID) {
			if err := q.UpdateWebAuthnCredential(ctx, postgres.UpdateWebAuthnCredentialParams{ID: row.ID, Credential: credJSON}); err != nil {
				utils.LogWarn(ctx, "UpdateWebAuthnCredential failed", zap.Error(err))
			}
			break
		}
	}

	if err := auth.DeleteWebAuthnLoginSession(ctx, redisClient, ceremonyID); err != nil {
		utils.LogWarn(ctx, "DeleteWebAuthnLoginSession failed", zap.Error(err))
	}

	ip := utils.ClientIPFromCtx(ctx)
	ua := utils.UserAgentFromCtx(ctx)
	// No auth_identities row is involved in a passkey login, so
	// identityID is left invalid/NULL — logins.identity_id is a nullable
	// FK for exactly this reason.
	return issueLoginSession(ctx, redisClient, q, resolvedUserPG, pgtype.UUID{}, resolvedUser.Username, resolvedUser.Role, ip, ua)
}

type PasskeyInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
}

// ListPasskeys returns the authenticated user's registered passkeys —
// labels and timestamps only, never key material.
func ListPasskeys(ctx context.Context, db *pgxpool.Pool, userID string) ([]PasskeyInfo, *utils.ErrorDetail) {
	userPG, ok := parseUserID(userID)
	if !ok {
		return nil, &utils.Errors.Unauthorized
	}
	q := postgres.New(db)
	rows, err := q.GetWebAuthnCredentialsByUserID(ctx, userPG)
	if err != nil {
		utils.LogError(ctx, "GetWebAuthnCredentialsByUserID failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}
	out := make([]PasskeyInfo, 0, len(rows))
	for _, row := range rows {
		out = append(out, PasskeyInfo{
			ID: row.ID.String(), Name: row.Name.String,
			CreatedAt: formatTimestamptz(row.CreatedAt), LastUsedAt: formatTimestamptz(row.LastUsedAt),
		})
	}
	return out, nil
}

// RenamePasskey updates a passkey's user-facing label. No password
// re-check — renaming doesn't affect what the credential can do.
func RenamePasskey(ctx context.Context, db *pgxpool.Pool, userID, passkeyID, name string) *utils.ErrorDetail {
	userPG, ok := parseUserID(userID)
	if !ok {
		return &utils.Errors.Unauthorized
	}
	pkPG, ok := parseUserID(passkeyID)
	if !ok {
		return &utils.Errors.PasskeyNotFound
	}
	nameTrimmed := strings.TrimSpace(name)
	if nameTrimmed == "" {
		return &utils.Errors.InvalidPayload
	}
	q := postgres.New(db)
	if !userOwnsPasskey(ctx, q, userPG, pkPG) {
		return &utils.Errors.PasskeyNotFound
	}
	if err := q.RenameWebAuthnCredential(ctx, postgres.RenameWebAuthnCredentialParams{
		Name: pgtype.Text{String: nameTrimmed, Valid: true}, ID: pkPG, UserID: userPG,
	}); err != nil {
		utils.LogError(ctx, "RenameWebAuthnCredential failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}
	return nil
}

// DeletePasskey removes a passkey, requiring the current password as
// re-authentication — see verifyCurrentPasswordForFactorAction; removing
// an authentication factor must not be possible with a stolen/replayed
// session token alone.
func DeletePasskey(ctx context.Context, db *pgxpool.Pool, userID, currentPassword, passkeyID string) *utils.ErrorDetail {
	userPG, ok := parseUserID(userID)
	if !ok {
		return &utils.Errors.Unauthorized
	}
	pkPG, ok := parseUserID(passkeyID)
	if !ok {
		return &utils.Errors.PasskeyNotFound
	}
	q := postgres.New(db)

	if errDetail := verifyCurrentPasswordForFactorAction(ctx, q, userPG, currentPassword); errDetail != nil {
		return errDetail
	}
	if !userOwnsPasskey(ctx, q, userPG, pkPG) {
		return &utils.Errors.PasskeyNotFound
	}
	if err := q.DeleteWebAuthnCredential(ctx, postgres.DeleteWebAuthnCredentialParams{ID: pkPG, UserID: userPG}); err != nil {
		utils.LogError(ctx, "DeleteWebAuthnCredential failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	if err := q.CreateAuditLog(ctx, postgres.CreateAuditLogParams{
		TargetUserID: userPG, Action: postgres.AuditActionMfaChange, Reason: textOrNull("Passkey removed"),
	}); err != nil {
		utils.LogWarn(ctx, "CreateAuditLog failed", zap.Error(err))
	}

	utils.LogInfo(ctx, "Passkey removed", zap.String("user_id", userID))
	return nil
}

func userOwnsPasskey(ctx context.Context, q *postgres.Queries, userPG, pkPG pgtype.UUID) bool {
	rows, err := q.GetWebAuthnCredentialsByUserID(ctx, userPG)
	if err != nil {
		return false
	}
	for _, row := range rows {
		if row.ID.Bytes == pkPG.Bytes {
			return true
		}
	}
	return false
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
