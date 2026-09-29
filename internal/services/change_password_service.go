package services

import (
	"context"
	"errors"

	"auth-api/internal/auth"
	"auth-api/internal/db/postgres"
	"auth-api/internal/utils"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// ChangePassword lets an already-authenticated user change their own
// password given their current one — as opposed to ResetPassword, which
// handles a forgotten password via an emailed token with no prior session.
// userID and currentSessionID come from the caller's verified access token
// (entities.UserContext), never from the request body.
//
// Unlike a reset, this does NOT revoke the session that made the request —
// only every OTHER session on the account. The caller already re-proved
// their identity by supplying the current password, so there's no reason to
// also log out the device they're using right now; every other device is
// still revoked, on the standard assumption that a password change often
// follows a suspicion that some other session is compromised.
func ChangePassword(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, userID, currentSessionID, currentPassword, newPassword, confirmPassword string) *utils.ErrorDetail {
	if !utils.IsValidPassword(newPassword) {
		utils.LogDebug(ctx, "New password failed validation")
		return &utils.Errors.InvalidPasswordFormat
	}
	if newPassword != confirmPassword {
		utils.LogDebug(ctx, "New password and confirmation don't match")
		return &utils.Errors.InvalidPasswordFormat
	}

	userPG, ok := parseUserID(userID)
	if !ok {
		return &utils.Errors.Unauthorized
	}
	sessionPG, ok := parseUserID(currentSessionID)
	if !ok {
		return &utils.Errors.Unauthorized
	}

	q := postgres.New(db)
	identity, err := q.GetEmailAuthByUserID(ctx, userPG)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// An authenticated request for a user_id with no email identity
			// shouldn't be reachable (JWTMiddleware already verified the
			// session), but fail safely rather than panic if it ever is.
			return &utils.Errors.Unauthorized
		}
		utils.LogError(ctx, "GetEmailAuthByUserID failed during password change", zap.Error(err))
		return &utils.Errors.InternalServerError
	}
	if identity.DeletedAt.Valid || (identity.Status.Valid && (identity.Status.UserStatus == postgres.UserStatusBanned || identity.Status.UserStatus == postgres.UserStatusDisabled)) {
		utils.LogInfo(ctx, "Password change blocked for non-usable account", zap.String("user_id", userID))
		return &utils.Errors.AccountNotUsable
	}

	ok, err = auth.VerifyPasswordPHC(currentPassword, identity.PasswordHash.String, true)
	if err != nil {
		utils.LogError(ctx, "VerifyPasswordPHC failed during password change", zap.Error(err))
		return &utils.Errors.InternalServerError
	}
	if !ok {
		utils.LogDebug(ctx, "Password change attempted with an incorrect current password", zap.String("user_id", userID))
		return &utils.Errors.InvalidCredentials
	}

	// Reject a "change" to the same password outright — both to avoid a
	// pointless rehash/session-revocation cycle, and because a client
	// silently no-op'ing this (e.g. a buggy "force password change"
	// prompt) is worth surfacing as an explicit error rather than a fake
	// success.
	if sameAsCurrent, err := auth.VerifyPasswordPHC(newPassword, identity.PasswordHash.String, true); err == nil && sameAsCurrent {
		return &utils.Errors.NewPasswordMatchesCurrent
	}

	newHash, err := auth.HashPasswordPHC(newPassword)
	if err != nil {
		utils.LogError(ctx, "HashPasswordPHC failed during password change", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	// Snapshot other active sessions BEFORE revoking in Postgres, to also
	// clear their Redis entries — see postgres.CompletePasswordChange's doc
	// comment, and CompletePasswordReset's for the fuller rationale.
	sessionIDs, err := q.ListActiveSessionIDs(ctx, userPG)
	if err != nil {
		utils.LogWarn(ctx, "ListActiveSessionIDs failed; other Postgres sessions will still be revoked, but their Redis entries may outlive them", zap.Error(err))
	}

	if err := postgres.CompletePasswordChange(ctx, db, identity.IdentityID, userPG, sessionPG, newHash); err != nil {
		utils.LogError(ctx, "CompletePasswordChange failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	for _, sessionID := range sessionIDs {
		if sessionID.String() == currentSessionID {
			continue
		}
		if err := auth.DeleteSession(ctx, sessionID.String(), redisClient); err != nil {
			utils.LogWarn(ctx, "Failed to delete Redis session after password change", zap.Error(err), zap.String("session_id", sessionID.String()))
		}
	}

	utils.LogInfo(ctx, "Password changed successfully", zap.String("user_id", userID))
	return nil
}
