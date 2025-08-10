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

-- name: CreateEmailAuth :exec
INSERT INTO auth_identities (user_id, provider, provider_user_id, password_hash)
VALUES (
  sqlc.arg(user_id), 
  'email',
  lower(sqlc.arg(email)),                    -- provider_user_id = normalized email
  sqlc.arg(password_hash)
);

-- name: UsernameExists :one
SELECT EXISTS (
  SELECT 1
  FROM users
  WHERE username = lower(sqlc.arg(username))
) AS exists;