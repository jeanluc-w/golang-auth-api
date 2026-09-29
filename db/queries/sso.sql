-- name: GetIdentityByProvider :one
-- Looks up an existing SSO login by (provider, provider_user_id) — the pair
-- that's actually stable and unique per external account, unlike email
-- (which a provider account could theoretically change).
SELECT
  u.id AS user_id,
  u.username,
  u.username_display,
  u.role,
  u.status,
  u.deleted_at,
  ai.id AS identity_id
FROM auth_identities ai
JOIN users u ON u.id = ai.user_id
WHERE ai.provider = sqlc.arg(provider) AND ai.provider_user_id = sqlc.arg(provider_user_id);

-- name: GetUserIDByEmail :one
-- Used only to detect a conflict (an account with this email already
-- exists under some other identity) — see services.SSOLogin's comment on
-- why that's treated as a conflict rather than auto-linked.
SELECT id FROM users WHERE lower(email) = lower(sqlc.arg(email));

-- name: CreateSSOUser :one
INSERT INTO users (email, username, username_display, role, origin)
VALUES (
  lower(sqlc.arg(email)),
  lower(sqlc.arg(username_display)),
  sqlc.arg(username_display),
  'user',
  sqlc.arg(origin)
)
RETURNING id, username, username_display, role;

-- name: CreateSSOIdentity :one
-- password_hash is always NULL for a non-email provider — enforced by the
-- CHECK constraint on auth_identities regardless, but explicit here too.
INSERT INTO auth_identities (user_id, provider, provider_user_id, password_hash)
VALUES (sqlc.arg(user_id), sqlc.arg(provider), sqlc.arg(provider_user_id), NULL)
RETURNING id;
