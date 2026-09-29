package services

import (
	"context"
	"errors"
	"strings"
	"time"

	"auth-api/config"
	"auth-api/internal/auth"
	"auth-api/internal/db/postgres"
	"auth-api/internal/emailer"
	"auth-api/internal/utils"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/resend/resend-go/v2"
	"go.uber.org/zap"
)

// RequestPasswordReset is step 1 of the password-reset flow: if the given
// email belongs to a usable email/password account, it generates a reset
// token, stores only its hash, and emails the raw token.
//
// The response is ALWAYS the same generic success regardless of whether the
// email exists, belongs to a deleted/banned/disabled account, or is within
// its regeneration cooldown. This is deliberately different from signup's
// StartEmailVerification (which reveals "email is taken"): revealing
// account existence during signup is an accepted UX tradeoff, but doing so
// on a password-reset endpoint is a textbook account-enumeration vector, so
// nothing here may vary the response based on it. Only a genuine
// validation/internal error is allowed to differ — see the comment below on
// why that's an acceptable, narrow exception.
func RequestPasswordReset(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, resendClient *resend.Client, email string) *utils.ErrorDetail {
	emailParsed := strings.ToLower(strings.TrimSpace(email))
	if !utils.IsValidEmail(emailParsed) {
		utils.LogDebug(ctx, "Invalid email format", zap.String("email", emailParsed))
		return &utils.Errors.InvalidEmailFormat
	}

	q := postgres.New(db)
	identity, err := q.GetEmailAuthByEmail(ctx, emailParsed)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			utils.LogError(ctx, "GetEmailAuthByEmail failed", zap.Error(err))
			return &utils.Errors.InternalServerError
		}
		utils.LogDebug(ctx, "Password reset requested for unknown email", zap.String("email", emailParsed))
		return nil
	}

	if identity.DeletedAt.Valid || (identity.Status.Valid && (identity.Status.UserStatus == postgres.UserStatusBanned || identity.Status.UserStatus == postgres.UserStatusDisabled)) {
		utils.LogInfo(ctx, "Password reset requested for non-usable account", zap.String("email", emailParsed))
		return nil
	}

	// Same regeneration-cooldown idea as StartEmailVerification, just
	// backed by the password_resets table (where this token already has to
	// live) instead of Redis.
	const regenerateWindow = 1 * time.Minute
	lastCreated, err := q.GetLatestPasswordResetForUser(ctx, identity.UserID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		utils.LogWarn(ctx, "GetLatestPasswordResetForUser failed; proceeding anyway", zap.Error(err))
	}
	if lastCreated.Valid && time.Since(lastCreated.Time) < regenerateWindow {
		utils.LogDebug(ctx, "Too early to regenerate password reset token", zap.String("email", emailParsed))
		return nil
	}

	rawToken, err := auth.RandomToken(32)
	if err != nil {
		utils.LogError(ctx, "Failed to generate password reset token", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	if _, err := q.CreatePasswordReset(ctx, postgres.CreatePasswordResetParams{
		UserID:     identity.UserID,
		ResetToken: auth.HashOpaqueToken(rawToken),
		ExpiresAt:  pgtype.Timestamptz{Time: time.Now().Add(config.Loaded.PasswordResetTTL), Valid: true},
		Source:     postgres.ResetSourceWeb,
	}); err != nil {
		utils.LogError(ctx, "Failed to create password reset record", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	// NOTE on the enumeration tradeoff mentioned above: a failure here (or
	// above, creating the record) DOES return a different response
	// (InternalServerError) than the nil/generic-success paths above it for
	// an unknown/non-usable email. In practice this isn't a usable oracle —
	// a real backend failure at this point almost always means the DB or
	// Resend itself is unhealthy, which affects every request regardless of
	// whether the email is real; silently swallowing it instead so every
	// path always returns identically would mean a broken email pipeline
	// never surfaces as an error to anyone.
	if _, err := emailer.SendPasswordResetEmail(rawToken, emailParsed, resendClient); err != nil {
		utils.LogError(ctx, "Failed to send password reset email", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	utils.LogInfo(ctx, "Password reset email sent", zap.String("email", emailParsed))
	return nil
}

// ResetPassword is step 2: given the raw token from RequestPasswordReset's
// email plus a new password, it verifies the token is unused/unexpired,
// updates the password, marks the token used, and — since a password reset
// is a security-sensitive event — revokes every session on the account
// (Postgres, checked by the refresh-token flow, and Redis, checked by
// access-token verification) so the account doesn't stay logged in
// anywhere on the old credentials.
func ResetPassword(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, rawToken, newPassword, confirmPassword string) *utils.ErrorDetail {
	tokenParsed := strings.TrimSpace(rawToken)
	if tokenParsed == "" {
		return &utils.Errors.InvalidOrExpiredToken
	}
	if !utils.IsValidPassword(newPassword) {
		utils.LogDebug(ctx, "New password failed validation")
		return &utils.Errors.InvalidPasswordFormat
	}
	if newPassword != confirmPassword {
		utils.LogDebug(ctx, "New password and confirmation don't match")
		return &utils.Errors.InvalidPasswordFormat
	}

	q := postgres.New(db)
	reset, err := q.GetActivePasswordReset(ctx, auth.HashOpaqueToken(tokenParsed))
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			utils.LogError(ctx, "GetActivePasswordReset failed", zap.Error(err))
			return &utils.Errors.InternalServerError
		}
		utils.LogDebug(ctx, "Password reset attempted with an invalid, expired, or already-used token")
		return &utils.Errors.InvalidOrExpiredToken
	}

	identity, err := q.GetEmailAuthByUserID(ctx, reset.UserID)
	if err != nil {
		utils.LogError(ctx, "GetEmailAuthByUserID failed during password reset", zap.Error(err))
		return &utils.Errors.InternalServerError
	}
	if identity.DeletedAt.Valid || (identity.Status.Valid && (identity.Status.UserStatus == postgres.UserStatusBanned || identity.Status.UserStatus == postgres.UserStatusDisabled)) {
		utils.LogInfo(ctx, "Password reset completion blocked for non-usable account", zap.String("user_id", reset.UserID.String()))
		return &utils.Errors.AccountNotUsable
	}

	newHash, err := auth.HashPasswordPHC(newPassword)
	if err != nil {
		utils.LogError(ctx, "HashPasswordPHC failed during password reset", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	// Snapshot which sessions are active BEFORE revoking them in Postgres,
	// so we know which Redis session/refresh keys to also delete —
	// Postgres and Redis are revoked/cleared as two separate steps (see
	// postgres.CompletePasswordReset's doc comment).
	sessionIDs, err := q.ListActiveSessionIDs(ctx, reset.UserID)
	if err != nil {
		utils.LogWarn(ctx, "ListActiveSessionIDs failed; Postgres sessions will still be revoked, but their Redis entries may outlive them", zap.Error(err))
	}

	if err := postgres.CompletePasswordReset(ctx, db, reset.ID, identity.IdentityID, reset.UserID, newHash); err != nil {
		utils.LogError(ctx, "CompletePasswordReset failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	for _, sessionID := range sessionIDs {
		if err := auth.DeleteSession(ctx, sessionID.String(), redisClient); err != nil {
			utils.LogWarn(ctx, "Failed to delete Redis session after password reset", zap.Error(err), zap.String("session_id", sessionID.String()))
		}
	}

	utils.LogInfo(ctx, "Password reset completed successfully", zap.String("user_id", reset.UserID.String()))
	return nil
}
