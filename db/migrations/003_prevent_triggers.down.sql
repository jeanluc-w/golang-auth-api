-- Drop triggers
DROP TRIGGER IF EXISTS trg_prevent_admin_deletion ON users;
DROP TRIGGER IF EXISTS trg_prevent_admin_demotion ON users;
DROP TRIGGER IF EXISTS trg_prevent_multiple_totp ON mfa_factors;

-- Drop functions
DROP FUNCTION IF EXISTS prevent_admin_deletion;
DROP FUNCTION IF EXISTS prevent_admin_demotion;
DROP FUNCTION IF EXISTS prevent_multiple_totp_mfa;
