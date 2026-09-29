package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CreatedSSOUser struct {
	UserID     pgtype.UUID
	IdentityID pgtype.UUID
	Username   string
}

// CreateSSOUserAndIdentity creates a brand-new user plus its SSO auth
// identity in one transaction — the SSO equivalent of CreateEmailUser for
// the email/password signup path. Only reached when SSOLogin has already
// confirmed no user exists with this email (see its doc comment on the
// account-linking policy).
func CreateSSOUserAndIdentity(ctx context.Context, db *pgxpool.Pool, email, usernameDisplay string, origin UserOrigin, provider ProviderName, providerUserID string) (*CreatedSSOUser, error) {
	var out *CreatedSSOUser
	err := WithTx(ctx, db, func(q *Queries) error {
		user, err := q.CreateSSOUser(ctx, CreateSSOUserParams{
			Email:           email,
			UsernameDisplay: usernameDisplay,
			Origin:          NullUserOrigin{UserOrigin: origin, Valid: true},
		})
		if err != nil {
			return err
		}
		identityID, err := q.CreateSSOIdentity(ctx, CreateSSOIdentityParams{
			UserID:         user.ID,
			Provider:       provider,
			ProviderUserID: providerUserID,
		})
		if err != nil {
			return err
		}
		out = &CreatedSSOUser{UserID: user.ID, IdentityID: identityID, Username: user.Username}
		return nil
	})
	return out, err
}
