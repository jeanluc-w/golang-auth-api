-- Only the 'totp' factor type has a working code path (see README's "Not
-- implemented" section for sms/email); every query here is scoped to it
-- explicitly rather than assuming it's the only row type mfa_factors will
-- ever hold.

-- name: UpsertPendingTOTPFactor :one
-- Starts (or restarts, if a previous attempt was abandoned) TOTP
-- enrollment. ON CONFLICT target matches the UNIQUE(user_id, type)
-- constraint — trg_prevent_multiple_totp additionally enforces this at the
-- database level regardless of what application code does.
INSERT INTO mfa_factors (user_id, type, secret, verified, enabled, failed_attempts, last_used_at, last_used_step)
VALUES (sqlc.arg(user_id), 'totp', sqlc.arg(secret), FALSE, FALSE, 0, NULL, NULL)
ON CONFLICT (user_id, type) DO UPDATE
  SET secret = excluded.secret,
      verified = FALSE,
      enabled = FALSE,
      failed_attempts = 0,
      last_used_at = NULL,
      last_used_step = NULL,
      created_at = now()
RETURNING id;

-- name: GetTOTPFactorByUserID :one
SELECT id, secret, verified, enabled, failed_attempts, last_used_step
FROM mfa_factors
WHERE user_id = sqlc.arg(user_id) AND type = 'totp';

-- name: VerifyTOTPFactor :exec
-- Confirms enrollment: the user has proven they can generate a valid code
-- with the secret, so the factor becomes active.
UPDATE mfa_factors
SET verified = TRUE, enabled = TRUE
WHERE id = sqlc.arg(id);

-- name: DeleteTOTPFactor :exec
-- Used to disable MFA outright; cascades to mfa_recovery_codes. A fresh
-- enrollment afterwards is a plain insert via UpsertPendingTOTPFactor, not
-- a conflict, since the row is actually gone.
DELETE FROM mfa_factors
WHERE user_id = sqlc.arg(user_id) AND type = 'totp';

-- name: RecordTOTPSuccess :exec
-- last_used_step is compared against the incoming code's time-step on every
-- attempt to reject replay of an already-used code within its own validity
-- window — TOTP's 30-second step alone doesn't prevent this.
UPDATE mfa_factors
SET last_used_at = now(), last_used_step = sqlc.arg(step), failed_attempts = 0
WHERE id = sqlc.arg(id);

-- name: IncrementTOTPFailedAttempts :exec
UPDATE mfa_factors
SET failed_attempts = failed_attempts + 1
WHERE id = sqlc.arg(id);

-- name: CreateMFARecoveryCode :exec
INSERT INTO mfa_recovery_codes (factor_id, code_hash)
VALUES (sqlc.arg(factor_id), sqlc.arg(code_hash));

-- name: DeleteMFARecoveryCodesByFactor :exec
-- Invalidates every existing recovery code for a factor — called when
-- (re-)verifying enrollment, since fresh codes are issued each time and the
-- previous batch (if any, from an earlier enrollment of the same factor
-- row) must not remain valid alongside them.
DELETE FROM mfa_recovery_codes WHERE factor_id = sqlc.arg(factor_id);

-- name: GetUnusedMFARecoveryCode :one
SELECT id
FROM mfa_recovery_codes
WHERE code_hash = sqlc.arg(code_hash) AND used_at IS NULL;

-- name: MarkMFARecoveryCodeUsed :exec
UPDATE mfa_recovery_codes
SET used_at = now()
WHERE id = sqlc.arg(id);
