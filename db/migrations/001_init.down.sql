-- Drop indexes
DROP INDEX IF EXISTS idx_logins_identity;
DROP INDEX IF EXISTS idx_logins_user;
DROP INDEX IF EXISTS idx_sessions_user_active;
DROP INDEX IF EXISTS idx_mfa_factors_user;
DROP INDEX IF EXISTS idx_password_resets_user;
DROP INDEX IF EXISTS idx_auth_identities_user;
DROP INDEX IF EXISTS idx_audit_logs_actor;
DROP INDEX IF EXISTS idx_audit_logs_target;

-- Drop tables (in dependency-safe reverse order)
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS logins;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS password_resets;
DROP TABLE IF EXISTS mfa_factors;
DROP TABLE IF EXISTS auth_identities;
DROP TABLE IF EXISTS users;

-- Drop types (reverse order of creation)
DROP TYPE IF EXISTS audit_action;
DROP TYPE IF EXISTS login_result;
DROP TYPE IF EXISTS reset_source;
DROP TYPE IF EXISTS mfa_type;
DROP TYPE IF EXISTS provider_name;
DROP TYPE IF EXISTS user_origin;
DROP TYPE IF EXISTS user_status;
DROP TYPE IF EXISTS user_role;
