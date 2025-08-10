CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Users table
CREATE TYPE user_role AS ENUM (
  'user',
  'moderator',
  'admin'
);
CREATE TYPE user_status AS ENUM (
  'active',
  'offline',
  'disabled',
  'banned'
);
CREATE TYPE user_origin AS ENUM (
  'email',
  'google',
  'apple'
);
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  username TEXT UNIQUE NOT NULL, -- canonical lowercase username (used for lookups/uniqueness)
  username_display TEXT NOT NULL, -- case-preserving display chosen by user
  profile_photo_url TEXT,
  display_name TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  status user_status DEFAULT 'disabled',
  role user_role DEFAULT 'user' NOT NULL,
  last_login TIMESTAMPTZ,
  last_password_change TIMESTAMPTZ, -- Null when only SSO is used
  origin user_origin, -- Useful for analytics of sign-ups, especially if multiple SSO providers are eventually used
  last_seen TIMESTAMPTZ, -- Last time the user was active in the app for live-time features
  deleted_at TIMESTAMPTZ, -- Allow soft deletes
  -- Ensure username display is alphanumeric, can include dots and underscores, but not start/end with a dot/underscore
  CONSTRAINT username_display_format
    CHECK (username_display ~ '^[A-Za-z0-9](?:[A-Za-z0-9._]{0,28}[A-Za-z0-9])?$'),
  -- Ensure canonical is always lowercase and matches display ignoring case
  CONSTRAINT username_canonical_lower
    CHECK (username = lower(username_display))
);


-- Auth identities (SSO or email)
CREATE TYPE provider_name AS ENUM (
  'email',
  'google',
  'apple'
);
CREATE TABLE auth_identities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  provider provider_name NOT NULL,  -- 'email', 'google', 'apple', etc.
  provider_user_id TEXT NOT NULL,
  password_hash TEXT, -- only for 'email' provider
  failed_attempts INTEGER DEFAULT 0,
  last_failed_at TIMESTAMPTZ,
  locked_at TIMESTAMPTZ,
  last_login TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now(),
  CHECK (
    (provider = 'email' AND password_hash IS NOT NULL)
    OR (provider != 'email' AND password_hash IS NULL)
  ),
  UNIQUE(provider, provider_user_id)
);


-- MFA (Multi-Factor Authentication) factors
CREATE TYPE mfa_type AS ENUM (
  'totp',
  'sms',
  'email'
);
CREATE TABLE mfa_factors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  authenticator_app_name TEXT,  -- e.g. 'Google Authenticator', 'Authy'
  type mfa_type NOT NULL,  -- 'totp', 'sms', 'email', etc.
  secret TEXT,         -- e.g. TOTP secret (base32), or phone/email depending on type
  enabled BOOLEAN DEFAULT FALSE,
  verified BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT now(),
  failed_attempts INTEGER DEFAULT 0,
  last_used_at TIMESTAMPTZ,
  revoked BOOLEAN DEFAULT FALSE,
  UNIQUE(user_id, type) -- Only one factor of each type per user
);


-- Password reset tokens for email provider
CREATE TYPE reset_source AS ENUM (
  'web',
  'mobile',
  'admin'
);
CREATE TABLE password_resets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  reset_token TEXT NOT NULL,  -- cryptographically secure, random string
  created_at TIMESTAMPTZ DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,  -- Null if not used yet
  backup_codes JSONB, -- JSON array of backup codes for password reset
  source reset_source NOT NULL  -- 'web', 'mobile', 'admin', etc.
);


-- Session management
CREATE TABLE sessions (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  refresh_token_hash TEXT, -- Hash of the refresh token for long-lived sessions
  rotated_at TIMESTAMPTZ, -- Track when the token was last rotated
  revoked BOOLEAN DEFAULT FALSE,
  revoked_at TIMESTAMPTZ,
  ip TEXT,
  user_agent TEXT,
  metadata JSONB
);

-- Login attempts and results
CREATE TYPE login_result AS ENUM (
  'success',
  'failed',
  'locked',
  'mfa_required'
);
CREATE TABLE logins (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  identity_id UUID REFERENCES auth_identities(id) ON DELETE SET NULL,
  result login_result NOT NULL,
  ip TEXT,
  user_agent TEXT,
  device_id TEXT, -- hash/fingerprint of user device if available
  location TEXT, -- e.g. city/region from GeoIP service
  created_at TIMESTAMPTZ DEFAULT now()
);


-- Autdit log for security events
CREATE TYPE audit_action AS ENUM (
  'update_user',
  'change_role',
  'change_status',
  'password_reset',
  'email_change',
  'mfa_change',
  'user_ban',
  'user_unban',
  'user_deleted',
  'admin_note'
);
CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  actor_id UUID, -- the userId of the user who performed the action
  actor_username TEXT,
  actor_email TEXT,

  target_user_id UUID, -- who was acted upon
  target_username TEXT,
  target_email TEXT,

  action audit_action NOT NULL,
  changes JSONB, -- e.g. {"status": ["active", "banned"]}
  reason TEXT,
  ip TEXT,
  user_agent TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);


-- Indexes for performance
CREATE INDEX idx_audit_logs_target ON audit_logs(target_user_id);
CREATE INDEX idx_audit_logs_actor ON audit_logs(actor_id);
CREATE INDEX idx_auth_identities_user ON auth_identities(user_id);
CREATE INDEX idx_password_resets_user ON password_resets(user_id);
CREATE INDEX idx_mfa_factors_user ON mfa_factors(user_id);
CREATE INDEX idx_sessions_user_active ON sessions(user_id) WHERE revoked = FALSE;
CREATE INDEX idx_logins_user ON logins(user_id);
CREATE INDEX idx_logins_identity ON logins(identity_id);
CREATE INDEX idx_logins_user_created ON logins(user_id, created_at DESC);
CREATE UNIQUE INDEX users_email_lower_uniq ON users (lower(email));
CREATE UNIQUE INDEX users_username_uniq ON users (username);