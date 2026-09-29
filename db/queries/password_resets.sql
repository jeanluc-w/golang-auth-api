-- name: CreatePasswordReset :one
-- reset_token stores HashOpaqueToken(raw), never the raw token itself — same
-- convention as sessions.refresh_token_hash.
INSERT INTO password_resets (
  user_id, reset_token, expires_at, source
) VALUES (
  sqlc.arg(user_id), sqlc.arg(reset_token), sqlc.arg(expires_at), sqlc.arg(source)
)
RETURNING id;

-- name: GetActivePasswordReset :one
-- Looks up an unused, unexpired reset request by its token hash. A missing
-- row must be treated identically whether the token never existed, already
-- expired, or was already consumed — see services.ResetPassword.
SELECT id, user_id, expires_at
FROM password_resets
WHERE reset_token = sqlc.arg(reset_token)
  AND used_at IS NULL
  AND expires_at > now();

-- name: GetLatestPasswordResetForUser :one
-- Used to enforce a regeneration cooldown between requests, mirroring
-- StartEmailVerification's cooldown. A missing row (no prior request) is a
-- normal, expected outcome for the caller to handle, not an error.
SELECT created_at
FROM password_resets
WHERE user_id = sqlc.arg(user_id)
ORDER BY created_at DESC
LIMIT 1;

-- name: MarkPasswordResetUsed :exec
UPDATE password_resets
SET used_at = now()
WHERE id = sqlc.arg(id);
