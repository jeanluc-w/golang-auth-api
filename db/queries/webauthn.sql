-- Passkey/WebAuthn credential queries — see
-- db/migrations/006_webauthn_credentials.up.sql for the storage-shape
-- rationale (the credential itself is stored as opaque JSON; only
-- credential_id is broken out as its own column, since it's the
-- login-time lookup key).

-- name: CreateWebAuthnCredential :one
INSERT INTO webauthn_credentials (user_id, credential_id, name, credential)
VALUES (sqlc.arg(user_id), sqlc.arg(credential_id), sqlc.arg(name), sqlc.arg(credential))
RETURNING id;

-- name: GetWebAuthnCredentialsByUserID :many
-- Used both to build the webauthn.User adapter (registration exclude-list,
-- and login's DiscoverableUserHandler, which matches an assertion's rawID
-- against exactly this list) and for the user-facing "your passkeys" view.
SELECT id, credential_id, name, credential, created_at, last_used_at
FROM webauthn_credentials
WHERE user_id = sqlc.arg(user_id)
ORDER BY created_at ASC;

-- name: UpdateWebAuthnCredential :exec
-- Overwrites the stored credential wholesale with the value
-- FinishLogin/FinishPasskeyLogin returns after a successful login — this
-- is how the authenticator's sign-count (clone detection) and backup-state
-- flags stay current. See the migration's comment for why a partial,
-- column-level update isn't used instead.
UPDATE webauthn_credentials
SET credential = sqlc.arg(credential), last_used_at = now()
WHERE id = sqlc.arg(id);

-- name: RenameWebAuthnCredential :exec
UPDATE webauthn_credentials
SET name = sqlc.arg(name)
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id);

-- name: DeleteWebAuthnCredential :exec
-- Scoped to (id, user_id) together, not just id — a user must never be
-- able to delete another user's passkey by guessing/enumerating its row id.
DELETE FROM webauthn_credentials
WHERE id = sqlc.arg(id) AND user_id = sqlc.arg(user_id);

-- name: CountWebAuthnCredentialsByUserID :one
SELECT count(*) FROM webauthn_credentials WHERE user_id = sqlc.arg(user_id);

-- name: GetUserForWebAuthnLogin :one
-- Used only inside the DiscoverableUserHandler callback during a passkey
-- login: the assertion's user handle identifies the account before
-- anything else about the request is known, so this intentionally isn't
-- scoped to a specific auth provider (unlike GetEmailAuthByUserID) — a
-- passkey can belong to an SSO-only account with no 'email' identity row.
SELECT id, username, role, status, deleted_at
FROM users
WHERE id = sqlc.arg(id);
