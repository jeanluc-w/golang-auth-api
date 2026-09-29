-- Thin wrappers around the cleanup functions defined in
-- db/migrations/004_revoke_triggers.up.sql. Nothing invokes those functions
-- on its own — see cmd/cron and internal/services/maintenance_service.go,
-- which run all of them on a schedule via an external cron/CronJob.

-- name: RemoveExpiredPasswordResets :exec
SELECT remove_expired_password_resets();

-- name: RemoveOldPasswordResets :exec
SELECT remove_old_password_resets();

-- name: RemoveOldLoginLogs :exec
SELECT remove_old_login_logs();

-- name: RemoveUnverifiedMFAFactors :exec
SELECT remove_unverified_mfa_factors();

-- name: RevokeExpiredSessions :exec
SELECT revoke_expired_sessions();

-- name: RevokeOldSessions :exec
SELECT revoke_old_sessions();
