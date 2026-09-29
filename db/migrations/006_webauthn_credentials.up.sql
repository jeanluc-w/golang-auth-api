-- Passkey/WebAuthn credentials (github.com/go-webauthn/webauthn).
--
-- The library's own package documentation ("Storage" section) recommends
-- either decomposing webauthn.Credential into explicit typed columns, or
-- storing the whole struct as a single serialized value; it explicitly
-- supports both and calls the latter a legitimate choice, not a shortcut,
-- when the former "genuinely does not fit". It's the one taken here: most
-- of Credential's substructures (CredentialFlags in particular) carry
-- unexported fields the library only reconstructs correctly via its own
-- JSON (un)marshaling, so decomposing them into individual columns means
-- either re-deriving that unexported state by hand or round-tripping
-- through the library's own marshaling anyway before splitting it up —
-- which is what storing the JSON directly already does, without the extra
-- step. credential_id is pulled out into its own indexed column since it's
-- the primary login-time lookup key (an assertion's rawID is matched
-- against it); everything else needed to verify a login — public key,
-- sign count, flags, attestation — lives in the credential JSONB blob and
-- is overwritten wholesale with the value FinishLogin/FinishPasskeyLogin
-- returns after every successful authentication (this is how sign_count
-- gets bumped for clone detection).
--
-- No separate "webauthn_users" table for the User Handle (WebAuthnID) the
-- library's docs otherwise recommend: this schema uses the account's own
-- users.id UUID directly as the handle. It's a deliberate simplification,
-- not an oversight — gen_random_uuid() output is already non-sequential
-- and never exposed as a guessable, low-entropy value elsewhere in this
-- schema, so reusing it avoids a second table and a bootstrap step for a
-- marginal privacy gain over a fully independent random handle.
CREATE TABLE webauthn_credentials (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id BYTEA NOT NULL UNIQUE, -- webauthn.Credential.ID; the authenticator's rawID, matched at login
  name TEXT, -- user-facing label, e.g. "MacBook Touch ID" — set by the client, not the authenticator
  credential JSONB NOT NULL, -- the full webauthn.Credential, encoding/json-serialized
  created_at TIMESTAMPTZ DEFAULT now(),
  last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_webauthn_credentials_user ON webauthn_credentials(user_id);
