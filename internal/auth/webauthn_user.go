package auth

import "github.com/go-webauthn/webauthn/webauthn"

// WebAuthnUser adapts an account's identity plus its existing passkeys to
// the webauthn.User interface the library needs for both registration (to
// exclude already-registered authenticators) and login (to match an
// assertion's signature against the right public key) ceremonies.
//
// WebAuthnID deliberately returns the account's own UUID bytes rather than
// a separately generated random handle, which the library's own package
// documentation otherwise recommends — see
// db/migrations/006_webauthn_credentials.up.sql for why that
// simplification is safe here.
type WebAuthnUser struct {
	ID          []byte
	Username    string
	DisplayName string
	Credentials []webauthn.Credential
}

func (u *WebAuthnUser) WebAuthnID() []byte                         { return u.ID }
func (u *WebAuthnUser) WebAuthnName() string                       { return u.Username }
func (u *WebAuthnUser) WebAuthnDisplayName() string                { return u.DisplayName }
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }
