package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CompletePasswordReset atomically marks a password reset token as used,
// updates the account's password hash, and revokes every session on the
// account, in a single transaction — so a crash between steps can never
// leave a reset token consumed without the password actually changing, or
// vice versa.
//
// It does NOT clear the corresponding Redis session/refresh keys; those are
// keyed by session ID, not user ID, so the caller must first fetch the
// active session IDs (ListActiveSessionIDs) and delete each one
// (auth.DeleteSession) — Postgres alone is the source of truth for whether
// a session is revoked (checked by the refresh-token flow), while Redis
// governs whether an already-issued, not-yet-expired access token still
// works.
func CompletePasswordReset(ctx context.Context, db *pgxpool.Pool, resetID, identityID, userID pgtype.UUID, newPasswordHash string) error {
	return WithTx(ctx, db, func(qtx *Queries) error {
		if err := qtx.MarkPasswordResetUsed(ctx, resetID); err != nil {
			return err
		}
		if err := qtx.UpdatePasswordHash(ctx, UpdatePasswordHashParams{
			PasswordHash: pgtype.Text{String: newPasswordHash, Valid: true},
			ID:           identityID,
		}); err != nil {
			return err
		}
		return qtx.RevokeAllUserSessions(ctx, userID)
	})
}
