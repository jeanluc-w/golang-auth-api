-- Queries backing the admin API surface (internal/services/admin_service.go).
-- Every mutating query here is meant to be run through postgres.WithActor,
-- which sets the transaction-local app.actor_id the audit-log triggers in
-- 002_log_triggers.up.sql read — without it, admin-performed changes would
-- still be logged, just with a NULL actor, indistinguishable from a user
-- acting on their own account.

-- name: SetActorID :exec
-- Must run in the same transaction as the query it's attributing — it uses
-- set_config's is_local=true, which is transaction-scoped, not
-- session-scoped (a pooled connection is reused across unrelated requests,
-- so a session-scoped setting would leak into the next one).
SELECT set_config('app.actor_id', sqlc.arg(actor_id)::text, true);

-- name: ListUsers :many
-- search matches username (canonical, lowercase) or email, case-insensitive
-- substring. Any of search/status/role may be omitted (NULL) to not filter
-- on that dimension.
SELECT id, email, username, username_display, status, role, created_at,
       last_login, deleted_at
FROM users
WHERE (sqlc.narg(search)::text IS NULL
         OR username ILIKE '%' || sqlc.narg(search)::text || '%'
         OR email ILIKE '%' || sqlc.narg(search)::text || '%')
  AND (sqlc.narg(status)::user_status IS NULL OR status = sqlc.narg(status)::user_status)
  AND (sqlc.narg(role)::user_role IS NULL OR role = sqlc.narg(role)::user_role)
ORDER BY created_at DESC
LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: CountUsers :one
SELECT count(*)
FROM users
WHERE (sqlc.narg(search)::text IS NULL
         OR username ILIKE '%' || sqlc.narg(search)::text || '%'
         OR email ILIKE '%' || sqlc.narg(search)::text || '%')
  AND (sqlc.narg(status)::user_status IS NULL OR status = sqlc.narg(status)::user_status)
  AND (sqlc.narg(role)::user_role IS NULL OR role = sqlc.narg(role)::user_role);

-- name: GetUserByIDAdmin :one
-- Unlike every other user lookup in this codebase, this deliberately does
-- NOT filter out soft-deleted accounts — an admin looking up a user by ID
-- (e.g. from an audit log entry) needs to find them either way.
SELECT id, email, username, username_display, status, role, created_at,
       last_login, last_password_change, origin, deleted_at
FROM users
WHERE id = sqlc.arg(id);

-- name: SetUserStatus :exec
UPDATE users
SET status = sqlc.arg(status)
WHERE id = sqlc.arg(id) AND deleted_at IS NULL;

-- name: SetUserRole :exec
-- trg_prevent_admin_demotion (003_prevent_triggers.up.sql) independently
-- blocks this at the database level if the target is currently an admin
-- and the new role isn't — a backstop against this application-level
-- check ever having a bug, not a substitute for it.
UPDATE users
SET role = sqlc.arg(role)
WHERE id = sqlc.arg(id) AND deleted_at IS NULL;

-- name: SoftDeleteUser :exec
UPDATE users
SET deleted_at = now()
WHERE id = sqlc.arg(id) AND deleted_at IS NULL;

-- name: ListAuditLogs :many
SELECT id, actor_id, actor_username, actor_email, target_user_id,
       target_username, target_email, action, changes, reason, ip,
       user_agent, created_at
FROM audit_logs
WHERE sqlc.narg(target_user_id)::uuid IS NULL OR target_user_id = sqlc.narg(target_user_id)::uuid
ORDER BY created_at DESC
LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: CountAuditLogs :one
SELECT count(*)
FROM audit_logs
WHERE sqlc.narg(target_user_id)::uuid IS NULL OR target_user_id = sqlc.narg(target_user_id)::uuid;

-- name: CreateAuditLog :exec
-- Used by admin_service.go for actions the field-diff triggers in
-- 002_log_triggers.up.sql don't (fully) cover on their own: force-logout
-- and admin-initiated password resets touch no users-table column at all,
-- and user_ban/user_unban/change_role/user_deleted here carry a specific,
-- searchable action type plus a human-written reason and request
-- ip/user_agent, none of which the generic 'update_user' trigger row
-- captures. Both rows existing side by side for the same action is
-- intentional, not duplication: the trigger row is a tamper-evident record
-- of the literal column change that fires no matter what application code
-- did or didn't do; this row is the human-readable "why".
INSERT INTO audit_logs (
  actor_id, actor_username, target_user_id, target_username, target_email,
  action, reason, ip, user_agent
) VALUES (
  sqlc.arg(actor_id), sqlc.arg(actor_username), sqlc.arg(target_user_id),
  sqlc.arg(target_username), sqlc.arg(target_email), sqlc.arg(action),
  sqlc.narg(reason), sqlc.narg(ip), sqlc.narg(user_agent)
);
