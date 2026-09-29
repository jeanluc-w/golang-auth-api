package services

import (
	"context"
	"errors"
	"strings"
	"time"

	"auth-api/config"
	"auth-api/internal/auth"
	"auth-api/internal/db/postgres"
	"auth-api/internal/entities"
	"auth-api/internal/utils"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type MFAEnrollResult struct {
	Secret          string // for manual entry, if the client can't scan a QR code
	ProvisioningURI string // otpauth://totp/... — render as a QR code
}

// EnrollMFA starts (or restarts, if a previous attempt was abandoned)
// TOTP enrollment for an already-authenticated user: it generates a new
// secret, encrypts it at rest, and stores it as an unverified factor. MFA
// isn't actually active yet — the account isn't protected, and no recovery
// codes exist — until the user proves they can generate a valid code with
// it via VerifyMFAEnrollment.
func EnrollMFA(ctx context.Context, db *pgxpool.Pool, userID, username string) (*MFAEnrollResult, *utils.ErrorDetail) {
	userPG, ok := parseUserID(userID)
	if !ok {
		return nil, &utils.Errors.Unauthorized
	}
	q := postgres.New(db)

	existing, err := q.GetTOTPFactorByUserID(ctx, userPG)
	if err == nil && existing.Enabled.Bool {
		return nil, &utils.Errors.MFAAlreadyEnabled
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		utils.LogError(ctx, "GetTOTPFactorByUserID failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	secret, uri, err := auth.GenerateTOTPSecret(config.Loaded.MFAIssuer, username)
	if err != nil {
		utils.LogError(ctx, "GenerateTOTPSecret failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}
	encryptedSecret, err := auth.EncryptMFASecret(secret)
	if err != nil {
		utils.LogError(ctx, "EncryptMFASecret failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	if _, err := q.UpsertPendingTOTPFactor(ctx, postgres.UpsertPendingTOTPFactorParams{
		UserID: userPG,
		Secret: pgtype.Text{String: encryptedSecret, Valid: true},
	}); err != nil {
		utils.LogError(ctx, "UpsertPendingTOTPFactor failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	utils.LogInfo(ctx, "MFA enrollment started", zap.String("user_id", userID))
	return &MFAEnrollResult{Secret: secret, ProvisioningURI: uri}, nil
}

type MFAVerifyEnrollResult struct {
	RecoveryCodes []string // shown exactly once — only hashes are persisted
}

// VerifyMFAEnrollment confirms a pending TOTP enrollment (from EnrollMFA) by
// checking a code generated with it, activating the factor, and issuing a
// fresh batch of one-time recovery codes.
func VerifyMFAEnrollment(ctx context.Context, db *pgxpool.Pool, userID, code string) (*MFAVerifyEnrollResult, *utils.ErrorDetail) {
	userPG, ok := parseUserID(userID)
	if !ok {
		return nil, &utils.Errors.Unauthorized
	}
	q := postgres.New(db)

	factor, err := q.GetTOTPFactorByUserID(ctx, userPG)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &utils.Errors.MFANotEnabled
		}
		utils.LogError(ctx, "GetTOTPFactorByUserID failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}
	if factor.Verified.Bool {
		return nil, &utils.Errors.MFAAlreadyEnabled
	}

	secret, err := auth.DecryptMFASecret(factor.Secret.String)
	if err != nil {
		utils.LogError(ctx, "DecryptMFASecret failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	step, valid := auth.ValidateTOTPCode(secret, strings.TrimSpace(code), factor.LastUsedStep.Int64, time.Now())
	if !valid {
		if err := q.IncrementTOTPFailedAttempts(ctx, factor.ID); err != nil {
			utils.LogWarn(ctx, "IncrementTOTPFailedAttempts failed", zap.Error(err))
		}
		utils.LogDebug(ctx, "MFA enrollment verification failed: incorrect code", zap.String("user_id", userID))
		return nil, &utils.Errors.InvalidMFACode
	}

	rawCodes := make([]string, 0, config.Loaded.MFARecoveryCodeCount)
	hashes := make([]string, 0, config.Loaded.MFARecoveryCodeCount)
	for i := 0; i < config.Loaded.MFARecoveryCodeCount; i++ {
		rawCode, err := auth.GenerateMFARecoveryCode()
		if err != nil {
			utils.LogError(ctx, "GenerateMFARecoveryCode failed", zap.Error(err))
			return nil, &utils.Errors.InternalServerError
		}
		rawCodes = append(rawCodes, rawCode)
		hashes = append(hashes, auth.HashOpaqueToken(rawCode))
	}

	if err := postgres.CompleteMFAEnrollment(ctx, db, factor.ID, step, hashes); err != nil {
		utils.LogError(ctx, "CompleteMFAEnrollment failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	utils.LogInfo(ctx, "MFA enrollment verified and activated", zap.String("user_id", userID))
	return &MFAVerifyEnrollResult{RecoveryCodes: rawCodes}, nil
}

// DisableMFA turns off MFA for an authenticated user. It requires the
// current password as re-authentication — disabling a security control
// must not be possible with just a stolen/replayed session token, since an
// attacker who has one still doesn't know the password.
func DisableMFA(ctx context.Context, db *pgxpool.Pool, userID, currentPassword string) *utils.ErrorDetail {
	userPG, ok := parseUserID(userID)
	if !ok {
		return &utils.Errors.Unauthorized
	}
	q := postgres.New(db)

	identity, err := q.GetEmailAuthByUserID(ctx, userPG)
	if err != nil {
		utils.LogError(ctx, "GetEmailAuthByUserID failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}
	ok2, err := auth.VerifyPasswordPHC(currentPassword, identity.PasswordHash.String, true)
	if err != nil {
		utils.LogError(ctx, "VerifyPasswordPHC failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}
	if !ok2 {
		return &utils.Errors.InvalidCredentials
	}

	if _, err := q.GetTOTPFactorByUserID(ctx, userPG); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &utils.Errors.MFANotEnabled
		}
		utils.LogError(ctx, "GetTOTPFactorByUserID failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	if err := q.DeleteTOTPFactor(ctx, userPG); err != nil {
		utils.LogError(ctx, "DeleteTOTPFactor failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	utils.LogInfo(ctx, "MFA disabled", zap.String("user_id", userID))
	return nil
}

// VerifyMFALogin is the second step of logging into an MFA-enabled account
// (see Login's MFARequired branch): given the challenge token from step one
// plus a TOTP or recovery code, it completes authentication exactly like a
// normal Login would.
func VerifyMFALogin(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, challengeToken, code string) (*LoginResult, *utils.ErrorDetail) {
	userID, challengeSessionID, err := auth.VerifyAndParseTemporaryJWT(ctx, redisClient, "Bearer "+challengeToken, entities.RoleMFAPending)
	if err != nil {
		utils.LogDebug(ctx, "MFA login challenge token invalid or expired", zap.Error(err))
		return nil, &utils.Errors.InvalidOrExpiredToken
	}
	userPG, ok := parseUserID(userID)
	if !ok {
		return nil, &utils.Errors.Unauthorized
	}
	q := postgres.New(db)

	factor, err := q.GetTOTPFactorByUserID(ctx, userPG)
	if err != nil || !factor.Enabled.Bool {
		// Shouldn't normally be reachable (the challenge is only ever
		// issued because MFA was enabled at that moment), but the account
		// could have had MFA disabled in the few seconds since — refuse
		// rather than silently skip the check that was supposed to happen.
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			utils.LogError(ctx, "GetTOTPFactorByUserID failed", zap.Error(err))
			return nil, &utils.Errors.InternalServerError
		}
		return nil, &utils.Errors.MFANotEnabled
	}

	codeParsed := strings.TrimSpace(code)
	authenticated := false

	if secret, decErr := auth.DecryptMFASecret(factor.Secret.String); decErr != nil {
		utils.LogError(ctx, "DecryptMFASecret failed", zap.Error(decErr))
		return nil, &utils.Errors.InternalServerError
	} else if step, valid := auth.ValidateTOTPCode(secret, codeParsed, factor.LastUsedStep.Int64, time.Now()); valid {
		if err := q.RecordTOTPSuccess(ctx, postgres.RecordTOTPSuccessParams{
			Step: pgtype.Int8{Int64: step, Valid: true},
			ID:   factor.ID,
		}); err != nil {
			utils.LogWarn(ctx, "RecordTOTPSuccess failed", zap.Error(err))
		}
		authenticated = true
	}

	// Not a valid TOTP code (or already replayed) — try it as a recovery
	// code before giving up. Recovery codes are generated uppercase; accept
	// lowercase input too rather than rejecting on a case mismatch alone.
	if !authenticated {
		codeHash := auth.HashOpaqueToken(strings.ToUpper(codeParsed))
		if recoveryID, rcErr := q.GetUnusedMFARecoveryCode(ctx, codeHash); rcErr == nil {
			if err := q.MarkMFARecoveryCodeUsed(ctx, recoveryID); err != nil {
				utils.LogWarn(ctx, "MarkMFARecoveryCodeUsed failed", zap.Error(err))
			}
			utils.LogInfo(ctx, "MFA login completed via recovery code", zap.String("user_id", userID))
			authenticated = true
		} else if !errors.Is(rcErr, pgx.ErrNoRows) {
			utils.LogError(ctx, "GetUnusedMFARecoveryCode failed", zap.Error(rcErr))
			return nil, &utils.Errors.InternalServerError
		}
	}

	if !authenticated {
		if err := q.IncrementTOTPFailedAttempts(ctx, factor.ID); err != nil {
			utils.LogWarn(ctx, "IncrementTOTPFailedAttempts failed", zap.Error(err))
		}
		utils.LogDebug(ctx, "MFA login verification failed", zap.String("user_id", userID))
		return nil, &utils.Errors.InvalidMFACode
	}

	identity, err := q.GetEmailAuthByUserID(ctx, userPG)
	if err != nil {
		utils.LogError(ctx, "GetEmailAuthByUserID failed during MFA login", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}
	// Re-check account status: it could have changed in the window between
	// the password step and this one.
	if identity.DeletedAt.Valid || (identity.Status.Valid && (identity.Status.UserStatus == postgres.UserStatusBanned || identity.Status.UserStatus == postgres.UserStatusDisabled)) {
		return nil, &utils.Errors.AccountNotUsable
	}

	if err := auth.DeleteTemporarySession(ctx, challengeSessionID, redisClient); err != nil {
		utils.LogWarn(ctx, "Failed to delete MFA challenge session", zap.Error(err))
	}

	ip := utils.ClientIPFromCtx(ctx)
	ua := utils.UserAgentFromCtx(ctx)
	return issueLoginSession(ctx, redisClient, q, identity.UserID, identity.IdentityID, identity.Username, identity.Role, ip, ua)
}

// parseUserID converts the string user ID carried in request context
// (entities.UserContext.ID, or a temporary JWT's subject) to the pgtype.UUID
// the generated queries expect.
func parseUserID(userID string) (pgtype.UUID, bool) {
	parsed, err := uuid.Parse(userID)
	if err != nil {
		return pgtype.UUID{}, false
	}
	return pgtype.UUID{Bytes: parsed, Valid: true}, true
}
