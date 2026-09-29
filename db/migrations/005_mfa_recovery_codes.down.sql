ALTER TABLE mfa_factors DROP COLUMN IF EXISTS last_used_step;
DROP TABLE IF EXISTS mfa_recovery_codes;
