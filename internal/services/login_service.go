package services

import (
	"context"
	"errors"
	"strings"
	"time"

	"auth-api/config"
	"auth-api/internal/auth"
	"auth-api/internal/db/postgres"
	"auth-api/internal/utils"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type LoginResult struct {
	AccessToken  string
	RefreshToken string
	UserID       string
	Username     string
}

// Login authenticates an email/password pair, applies failed-attempt
// lockout, and on success issues a new access/refresh token pair.
//
// Security notes:
//   - Every rejection path (unknown email, wrong password, locked account)
//     returns the same InvalidCredentials error to the caller for anything
//     that happens *before* the password is verified, so a client can't
//     enumerate which emails have accounts.
//   - Unknown-email and malformed-input attempts still run a dummy password
//     hash so the response time doesn't itself leak that signal.
//   - Account status (banned/disabled) is only revealed *after* a correct
//     password, since only someone who already knows the password gains
//     anything from that information.
func Login(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, email, password string) (*LoginResult, *utils.ErrorDetail) {
	emailParsed := strings.ToLower(strings.TrimSpace(email))
	ip := utils.ClientIPFromCtx(ctx)
	ua := utils.UserAgentFromCtx(ctx)
	q := postgres.New(db)

	if !utils.IsValidEmail(emailParsed) || password == "" || len(password) > 256 {
		auth.VerifyDummyPassword(password)
		return nil, &utils.Errors.InvalidCredentials
	}

	identity, err := q.GetEmailAuthByEmail(ctx, emailParsed)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			utils.LogError(ctx, "GetEmailAuthByEmail failed", zap.Error(err))
			return nil, &utils.Errors.InternalServerError
		}
		auth.VerifyDummyPassword(password)
		recordLoginAttempt(ctx, q, pgtype.UUID{}, pgtype.UUID{}, postgres.LoginResultFailed, ip, ua)
		return nil, &utils.Errors.InvalidCredentials
	}

	if identity.DeletedAt.Valid {
		auth.VerifyDummyPassword(password)
		recordLoginAttempt(ctx, q, identity.UserID, identity.IdentityID, postgres.LoginResultFailed, ip, ua)
		return nil, &utils.Errors.InvalidCredentials
	}

	// Checked before verifying the password: once locked, further guesses
	// don't matter until the lock window passes, so there's no reason to
	// pay the argon2 cost (and doing so would let an attacker distinguish
	// "locked" from "wrong password" by response time).
	if identity.LockedAt.Valid && time.Since(identity.LockedAt.Time) < config.Loaded.LoginLockDuration {
		auth.VerifyDummyPassword(password)
		recordLoginAttempt(ctx, q, identity.UserID, identity.IdentityID, postgres.LoginResultLocked, ip, ua)
		return nil, &utils.Errors.AccountLocked
	}

	ok, err := auth.VerifyPasswordPHC(password, identity.PasswordHash.String, true)
	if err != nil {
		utils.LogError(ctx, "VerifyPasswordPHC failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	if !ok {
		recordLoginAttempt(ctx, q, identity.UserID, identity.IdentityID, postgres.LoginResultFailed, ip, ua)
		attempts, err := q.IncrementFailedLoginAttempts(ctx, identity.IdentityID)
		if err != nil {
			utils.LogError(ctx, "IncrementFailedLoginAttempts failed", zap.Error(err))
		} else if int(attempts.Int32) >= config.Loaded.LoginMaxFailedAttempts {
			if err := q.LockAuthIdentity(ctx, identity.IdentityID); err != nil {
				utils.LogError(ctx, "LockAuthIdentity failed", zap.Error(err))
			}
		}
		return nil, &utils.Errors.InvalidCredentials
	}

	// From here on the caller has proven they know the password, so it's
	// safe to give more specific feedback.
	if identity.Status.Valid && (identity.Status.UserStatus == postgres.UserStatusBanned || identity.Status.UserStatus == postgres.UserStatusDisabled) {
		recordLoginAttempt(ctx, q, identity.UserID, identity.IdentityID, postgres.LoginResultFailed, ip, ua)
		utils.LogInfo(ctx, "Login blocked for non-usable account status", zap.String("status", string(identity.Status.UserStatus)))
		return nil, &utils.Errors.AccountNotUsable
	}

	if err := q.ResetFailedLoginAttempts(ctx, identity.IdentityID); err != nil {
		utils.LogWarn(ctx, "ResetFailedLoginAttempts failed", zap.Error(err))
	}
	if err := q.TouchUserLastLogin(ctx, identity.UserID); err != nil {
		utils.LogWarn(ctx, "TouchUserLastLogin failed", zap.Error(err))
	}

	// Transparently upgrade the stored hash if it used retired argon2
	// params or a rotated-out pepper. Best-effort: failure here shouldn't
	// block the login that already succeeded.
	if shouldRehash, err := auth.ShouldRehashActive(identity.PasswordHash.String); err != nil {
		utils.LogWarn(ctx, "ShouldRehashActive failed", zap.Error(err))
	} else if shouldRehash {
		if newHash, err := auth.HashPasswordPHC(password); err != nil {
			utils.LogWarn(ctx, "Failed to rehash password", zap.Error(err))
		} else if err := q.UpdatePasswordHash(ctx, postgres.UpdatePasswordHashParams{
			PasswordHash: pgtype.Text{String: newHash, Valid: true},
			ID:           identity.IdentityID,
		}); err != nil {
			utils.LogWarn(ctx, "Failed to persist rehashed password", zap.Error(err))
		}
	}

	userIDStr := identity.UserID.String()
	tokens, err := auth.GenerateUserTokens(
		ctx,
		redisClient,
		userIDStr,
		identity.Username,
		string(identity.Role),
		config.Loaded.AccessTTL,
		config.Loaded.RefreshTTL,
	)
	if err != nil {
		utils.LogError(ctx, "Failed to generate tokens for login", zap.Error(err))
		return nil, &utils.Errors.TokenGenerationFailed
	}

	refreshHash := auth.HashRefreshToken(tokens.RefreshToken)
	_, err = postgres.CreateRefreshSession(ctx, q, postgres.RefreshSessionInput{
		SessionID:        tokens.SessionID,
		UserID:           identity.UserID,
		ExpiresAt:        tokens.RefreshExp,
		RefreshTokenHash: refreshHash,
		IP:               ip,
		UserAgent:        ua,
	})
	if err != nil {
		_ = auth.DeleteSession(ctx, tokens.SessionID, redisClient)
		utils.LogError(ctx, "CreateRefreshSession failed during login", zap.Error(err))
		return nil, &utils.Errors.TokenGenerationFailed
	}

	recordLoginAttempt(ctx, q, identity.UserID, identity.IdentityID, postgres.LoginResultSuccess, ip, ua)
	utils.LogInfo(ctx, "Login successful", zap.String("user_id", userIDStr))

	return &LoginResult{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		UserID:       userIDStr,
		Username:     identity.Username,
	}, nil
}

// recordLoginAttempt is best-effort: a failure to write the audit row must
// never block or fail the login/refresh flow itself.
func recordLoginAttempt(ctx context.Context, q *postgres.Queries, userID, identityID pgtype.UUID, result postgres.LoginResult, ip, ua string) {
	if err := q.RecordLoginAttempt(ctx, postgres.RecordLoginAttemptParams{
		UserID:     userID,
		IdentityID: identityID,
		Result:     result,
		Ip:         pgtype.Text{String: ip, Valid: ip != ""},
		UserAgent:  pgtype.Text{String: ua, Valid: ua != ""},
	}); err != nil {
		utils.LogWarn(ctx, "RecordLoginAttempt failed", zap.Error(err))
	}
}
