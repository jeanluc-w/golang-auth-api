-- Users table
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  username TEXT UNIQUE,
  display_name TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  is_active BOOLEAN DEFAULT TRUE,
  last_login TIMESTAMPTZ
);

-- Enforce username regex using check constraint
ALTER TABLE users ADD CONSTRAINT username_format CHECK (
  username ~ '^[a-zA-Z0-9](?:[a-zA-Z0-9._]{0,28}[a-zA-Z0-9])?$'
);

-- Auth identities (SSO or email)
CREATE TABLE auth_identities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id),
  provider TEXT NOT NULL,  -- 'email', 'google', 'apple', etc.
  provider_user_id TEXT NOT NULL,
  password_hash TEXT, -- only for 'email' provider
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(provider, provider_user_id)
);

-- Session management
CREATE TABLE sessions (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT now(),
  ip TEXT,
  user_agent TEXT,
  metadata JSONB
);
