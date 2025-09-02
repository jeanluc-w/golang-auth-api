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