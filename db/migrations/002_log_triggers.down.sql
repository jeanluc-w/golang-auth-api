-- Drop triggers
DROP TRIGGER IF EXISTS trg_auth_identity_update_audit ON auth_identities;
DROP TRIGGER IF EXISTS trg_mfa_factor_update_audit ON mfa_factors;
DROP TRIGGER IF EXISTS trg_password_reset_used ON password_resets;
DROP TRIGGER IF EXISTS trg_user_delete_audit ON users;
DROP TRIGGER IF EXISTS trg_user_update_audit ON users;

-- Drop functions
DROP FUNCTION IF EXISTS log_auth_identity_update;
DROP FUNCTION IF EXISTS log_mfa_factor_update;
DROP FUNCTION IF EXISTS log_password_reset_used;
DROP FUNCTION IF EXISTS log_user_delete;
DROP FUNCTION IF EXISTS log_user_update;
