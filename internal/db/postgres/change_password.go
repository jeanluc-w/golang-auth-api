package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CompletePasswordChange atomically updates an authenticated user's password
// hash and revokes every OTHER session on the account (the caller's current
// session, identified by currentSessionID, is left alone — they just proved
// they know the new password by making this very request). See
// CompletePasswordReset for the equivalent used by the forgotten-password
// flow, which has no "current session" to preserve and revokes everything.
func CompletePasswordChange(ctx context.Context, db *pgxpool.Pool, identityID, userID, currentSessionID pgtype.UUID, newPasswordHash string) error {
	return WithTx(ctx, db, func(qtx *Queries) error {
		if err := qtx.UpdatePasswordHash(ctx, UpdatePasswordHashParams{
			PasswordHash: pgtype.Text{String: newPasswordHash, Valid: true},
			ID:           identityID,
		}); err != nil {
			return err
		}
		return qtx.RevokeAllOtherUserSessions(ctx, RevokeAllOtherUserSessionsParams{
			UserID:           userID,
			CurrentSessionID: currentSessionID,
		})
	})
}
