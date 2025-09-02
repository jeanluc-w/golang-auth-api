
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