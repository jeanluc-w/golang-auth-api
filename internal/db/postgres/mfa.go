package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CompleteMFAEnrollment atomically confirms a TOTP factor (marks it
// verified+enabled, records the step the confirmation code matched) and
// issues a fresh batch of recovery codes, replacing any left over from a
// previous enrollment of the same factor row. All of it happens in one
// transaction so a factor is never left "verified" without any recovery
// codes to fall back on, or vice versa.
func CompleteMFAEnrollment(ctx context.Context, db *pgxpool.Pool, factorID pgtype.UUID, matchedStep int64, recoveryCodeHashes []string) error {
	return WithTx(ctx, db, func(qtx *Queries) error {
		if err := qtx.VerifyTOTPFactor(ctx, factorID); err != nil {
			return err
		}
		if err := qtx.RecordTOTPSuccess(ctx, RecordTOTPSuccessParams{
			Step: pgtype.Int8{Int64: matchedStep, Valid: true},
			ID:   factorID,
		}); err != nil {
			return err
		}
		if err := qtx.DeleteMFARecoveryCodesByFactor(ctx, factorID); err != nil {
			return err
		}
		for _, hash := range recoveryCodeHashes {
			if err := qtx.CreateMFARecoveryCode(ctx, CreateMFARecoveryCodeParams{
				FactorID: factorID,
				CodeHash: hash,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

// CompleteOTPFactorEnrollment is CompleteMFAEnrollment's counterpart for
// email/SMS factors: same atomicity guarantee (never verified without
// recovery codes or vice versa), just without a matched-step to record,
// since those factor types have no TOTP-style time-step to replay-guard.
func CompleteOTPFactorEnrollment(ctx context.Context, db *pgxpool.Pool, factorID pgtype.UUID, recoveryCodeHashes []string) error {
	return WithTx(ctx, db, func(qtx *Queries) error {
		if err := qtx.VerifyOTPFactor(ctx, factorID); err != nil {
			return err
		}
		if err := qtx.RecordOTPFactorSuccess(ctx, factorID); err != nil {
			return err
		}
		if err := qtx.DeleteMFARecoveryCodesByFactor(ctx, factorID); err != nil {
			return err
		}
		for _, hash := range recoveryCodeHashes {
			if err := qtx.CreateMFARecoveryCode(ctx, CreateMFARecoveryCodeParams{
				FactorID: factorID,
				CodeHash: hash,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}
