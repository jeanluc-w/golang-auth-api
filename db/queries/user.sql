-- name: CreateUser :one
INSERT INTO users (email, username, role, origin)
VALUES ($1, $2, 'user', 'email')
RETURNING id, username;

-- name: CreateEmailAuth :exec
INSERT INTO auth_identities (user_id, provider, provider_user_id, password_hash)
VALUES ($1, 'email', $2, $3);
