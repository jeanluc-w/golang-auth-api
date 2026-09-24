-- name: CreateUser :one
INSERT INTO users (email, username, username_display, role, origin)
VALUES (
  lower(sqlc.arg(email)),                    -- normalize email
  lower(sqlc.arg(username_display)),         -- canonical username (lowercased)
  sqlc.arg(username_display),                -- case-preserving display
  'user',
  'email'
)
RETURNING id, email, username, username_display, role;

-- name: UsernameExists :one
SELECT EXISTS (
  SELECT 1
  FROM users
  WHERE username = lower(sqlc.arg(username))
) AS exists;

-- name: GetUserByID :one
-- Used by the refresh-token flow to re-derive current username/role/status
-- for the new access token, rather than trusting the (possibly stale,
-- already-expired) claims of the token being refreshed.
SELECT id, username, username_display, role, status, deleted_at
FROM users
WHERE id = sqlc.arg(id);

-- name: TouchUserLastLogin :exec
UPDATE users
SET last_login = now(), last_seen = now()
WHERE id = sqlc.arg(id);