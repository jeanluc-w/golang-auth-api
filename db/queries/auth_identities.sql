
-- name: CreateEmailAuth :exec
INSERT INTO auth_identities (user_id, provider, provider_user_id, password_hash)
VALUES (
  sqlc.arg(user_id), 
  'email',
  lower(sqlc.arg(email)),                    -- provider_user_id = normalized email
  sqlc.arg(password_hash)
);

-- name: IsEmailRegistered :one
SELECT EXISTS (
  SELECT 1
  FROM auth_identities
  WHERE provider = 'email' AND provider_user_id = lower(sqlc.arg(email))
) AS exists;

-- name: GetEmailAuthByEmail :one
-- Looks up a user's email auth identity by their login email. Used only by
-- the login flow; a missing row must be treated identically (timing- and
-- response-wise) to a wrong password by the caller, to avoid leaking which
-- emails have accounts.
SELECT
  u.id AS user_id,
  u.username,
  u.username_display,
  u.role,
  u.status,
  u.deleted_at,
  ai.id AS identity_id,
  ai.password_hash,
  ai.failed_attempts,
  ai.locked_at
FROM auth_identities ai
JOIN users u ON u.id = ai.user_id
WHERE ai.provider = 'email' AND ai.provider_user_id = lower(sqlc.arg(email));

-- name: IncrementFailedLoginAttempts :one
UPDATE auth_identities
SET failed_attempts = failed_attempts + 1,
    last_failed_at = now()
WHERE id = sqlc.arg(id)
RETURNING failed_attempts;

-- name: LockAuthIdentity :exec
UPDATE auth_identities
SET locked_at = now()
WHERE id = sqlc.arg(id);

-- name: ResetFailedLoginAttempts :exec
-- Clears lockout state after a successful login.
UPDATE auth_identities
SET failed_attempts = 0,
    locked_at = NULL,
    last_login = now()
WHERE id = sqlc.arg(id);

-- name: UpdatePasswordHash :exec
-- Used to transparently rehash a password on successful login when it was
-- hashed with retired parameters or a rotated-out pepper.
UPDATE auth_identities
SET password_hash = sqlc.arg(password_hash)
WHERE id = sqlc.arg(id);