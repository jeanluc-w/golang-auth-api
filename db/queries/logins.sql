-- name: RecordLoginAttempt :exec
-- user_id and identity_id are nullable: an attempt against an email with no
-- account still gets logged (IP/UA/time only) for anomaly detection.
INSERT INTO logins (user_id, identity_id, result, ip, user_agent)
VALUES (sqlc.narg(user_id), sqlc.narg(identity_id), sqlc.arg(result), sqlc.arg(ip), sqlc.arg(user_agent));
