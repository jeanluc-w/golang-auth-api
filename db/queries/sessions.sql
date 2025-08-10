-- name: CreateRefreshSession :one
INSERT INTO sessions (
  id, user_id, expires_at, refresh_token_hash, ip, user_agent, metadata
) VALUES (
  sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(expires_at), sqlc.arg(refresh_token_hash),
  sqlc.arg(ip), sqlc.arg(user_agent), sqlc.arg(metadata)
)
RETURNING id, user_id, expires_at, revoked;

-- name: RotateRefreshSession :one
UPDATE sessions
SET refresh_token_hash = sqlc.arg(refresh_token_hash),
    rotated_at = now(),
    expires_at = sqlc.arg(expires_at)
WHERE id = sqlc.arg(id)
  AND revoked = FALSE
RETURNING id, user_id, expires_at;

-- name: RevokeSession :exec
UPDATE sessions
SET revoked = TRUE, revoked_at = now()
WHERE id = sqlc.arg(id) AND revoked = FALSE;

-- name: GetRefreshSession :one
SELECT id, user_id, expires_at, refresh_token_hash, revoked
FROM sessions
WHERE id = sqlc.arg(id);