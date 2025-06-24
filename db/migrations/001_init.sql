-- Users table
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  username TEXT UNIQUE,
  display_name TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
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
  UNIQUE(provider, provider_user_id)
);

-- Restaurants
CREATE TABLE restaurants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  location GEOGRAPHY(POINT, 4326),
  description TEXT,
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Lists
CREATE TABLE lists (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  visibility TEXT NOT NULL DEFAULT 'private',
  owner_id UUID REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT now()
);

-- List Items
CREATE TABLE list_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  list_id UUID REFERENCES lists(id),
  restaurant_id UUID REFERENCES restaurants(id),
  added_by UUID REFERENCES users(id),
  note TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Reviews
CREATE TABLE reviews (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id),
  restaurant_id UUID REFERENCES restaurants(id),
  rating TEXT NOT NULL CHECK (rating IN ('Not for Me', 'Like It', 'Love It')),
  comment TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);
