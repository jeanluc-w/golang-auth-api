-- Drop maintenance functions
DROP FUNCTION IF EXISTS remove_expired_password_resets;
DROP FUNCTION IF EXISTS remove_old_login_logs;
DROP FUNCTION IF EXISTS remove_old_password_resets;
DROP FUNCTION IF EXISTS remove_unverified_mfa_factors;
DROP FUNCTION IF EXISTS revoke_expired_sessions;
DROP FUNCTION IF EXISTS revoke_old_sessions;
DROP FUNCTION IF EXISTS revoke_all_other_sessions;
