-- One-time-use recovery codes for MFA, issued when a factor is first
-- verified (see services.VerifyMFAEnrollment). Only the hash is ever
-- stored — same HashOpaqueToken convention as refresh/reset tokens — since
-- these are already high-entropy, app-generated random values, not
-- something a user chose and might reuse elsewhere.
CREATE TABLE mfa_recovery_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  factor_id UUID NOT NULL REFERENCES mfa_factors(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at TIMESTAMPTZ, -- NULL until consumed; a used code is never deleted, only marked, for audit purposes
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_mfa_recovery_codes_factor ON mfa_recovery_codes(factor_id);

-- A given factor's recovery codes are looked up by hash directly (there's
-- no user_id column to filter by first), so the hash itself needs to be
-- unique to make that lookup a simple, fast equality query.
CREATE UNIQUE INDEX idx_mfa_recovery_codes_hash ON mfa_recovery_codes(code_hash);

-- Replay/anti-abuse: the last TOTP time-step successfully used per factor,
-- so a captured code can't be replayed again within its own validity
-- window (TOTP alone doesn't prevent this — the same 6 digits stay valid
-- for the whole ~30s step).
ALTER TABLE mfa_factors ADD COLUMN last_used_step BIGINT;
