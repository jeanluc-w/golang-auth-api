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
	"auth-api/internal/entities"
	"auth-api/internal/utils"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/resend/resend-go/v2"
	"go.uber.org/zap"
)

// mfaOTPMaxAttempts caps guesses against a single delivered email/SMS
// code — the code itself lives in Redis (see internal/auth/mfa_otp_code.go)
// with its own expiry, but a short-lived code is still guessable if
// attempts within its window aren't separately bounded, the same reasoning
// StartEmailVerification's signup code already applies.
const mfaOTPMaxAttempts = 5

// mfaOTPRegenerateWindow throttles how often a new code can be requested
// for the same purpose, matching the cooldown already used for the signup
// verification code and password-reset tokens.
const mfaOTPRegenerateWindow = 1 * time.Minute

// EnrollEmailMFA starts email-based MFA enrollment: sends a one-time code
// to the account's own registered email address (never a caller-supplied
// one — enrollment always targets the address already proven at signup,
// so there's no separate ownership check to get wrong) and stores an
// unverified 'email' factor. MFA isn't active — the account isn't
// protected, no recovery codes exist — until VerifyEmailMFAEnrollment
// confirms the code.
func EnrollEmailMFA(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, resendClient *resend.Client, userID string) *utils.ErrorDetail {
	userPG, ok := parseUserID(userID)
	if !ok {
		return &utils.Errors.Unauthorized
	}
	q := postgres.New(db)

	existing, err := q.GetOTPFactorByUserID(ctx, postgres.GetOTPFactorByUserIDParams{UserID: userPG, Type: postgres.MfaTypeEmail})
	if err == nil && existing.Enabled.Bool {
		return &utils.Errors.MFAAlreadyEnabled
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		utils.LogError(ctx, "GetOTPFactorByUserID(email) failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	email, err := q.GetUserEmailByID(ctx, userPG)
	if err != nil {
		utils.LogError(ctx, "GetUserEmailByID failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	if errDetail := sendMFAEmailCode(ctx, redisClient, resendClient, userID, email, "enroll"); errDetail != nil {
		return errDetail
	}

	if _, err := q.UpsertPendingOTPFactor(ctx, postgres.UpsertPendingOTPFactorParams{UserID: userPG, Type: postgres.MfaTypeEmail}); err != nil {
		utils.LogError(ctx, "UpsertPendingOTPFactor(email) failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	utils.LogInfo(ctx, "Email MFA enrollment started", zap.String("user_id", userID))
	return nil
}

// VerifyEmailMFAEnrollment confirms a pending email-MFA enrollment (from
// EnrollEmailMFA) by checking the emailed code, activating the factor, and
// issuing a fresh batch of one-time recovery codes.
func VerifyEmailMFAEnrollment(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, userID, code string) (*MFAVerifyEnrollResult, *utils.ErrorDetail) {
	userPG, ok := parseUserID(userID)
	if !ok {
		return nil, &utils.Errors.Unauthorized
	}
	q := postgres.New(db)

	factor, err := q.GetOTPFactorByUserID(ctx, postgres.GetOTPFactorByUserIDParams{UserID: userPG, Type: postgres.MfaTypeEmail})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &utils.Errors.MFANotEnabled
		}
		utils.LogError(ctx, "GetOTPFactorByUserID(email) failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}
	if factor.Verified.Bool {
		return nil, &utils.Errors.MFAAlreadyEnabled
	}

	if errDetail := verifyMFAOTPCode(ctx, redisClient, q, "email", "enroll", userID, factor.ID, code); errDetail != nil {
		return nil, errDetail
	}

	rawCodes, hashes, errDetail := generateRecoveryCodes(ctx, config.Loaded.MFARecoveryCodeCount)
	if errDetail != nil {
		return nil, errDetail
	}

	if err := postgres.CompleteOTPFactorEnrollment(ctx, db, factor.ID, hashes); err != nil {
		utils.LogError(ctx, "CompleteOTPFactorEnrollment(email) failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}
	if err := auth.DeleteMFAOTPCode(ctx, redisClient, "email", "enroll", userID); err != nil {
		utils.LogWarn(ctx, "DeleteMFAOTPCode failed", zap.Error(err))
	}

	utils.LogInfo(ctx, "Email MFA enrollment verified and activated", zap.String("user_id", userID))
	return &MFAVerifyEnrollResult{RecoveryCodes: rawCodes}, nil
}

// DisableEmailMFA turns off email-based MFA, requiring the current
// password as re-authentication — see verifyCurrentPasswordForFactorAction.
func DisableEmailMFA(ctx context.Context, db *pgxpool.Pool, userID, currentPassword string) *utils.ErrorDetail {
	userPG, ok := parseUserID(userID)
	if !ok {
		return &utils.Errors.Unauthorized
	}
	q := postgres.New(db)

	if errDetail := verifyCurrentPasswordForFactorAction(ctx, q, userPG, currentPassword); errDetail != nil {
		return errDetail
	}

	if _, err := q.GetOTPFactorByUserID(ctx, postgres.GetOTPFactorByUserIDParams{UserID: userPG, Type: postgres.MfaTypeEmail}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &utils.Errors.MFANotEnabled
		}
		utils.LogError(ctx, "GetOTPFactorByUserID(email) failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	if err := q.DeleteOTPFactor(ctx, postgres.DeleteOTPFactorParams{UserID: userPG, Type: postgres.MfaTypeEmail}); err != nil {
		utils.LogError(ctx, "DeleteOTPFactor(email) failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	utils.LogInfo(ctx, "Email MFA disabled", zap.String("user_id", userID))
	return nil
}

// SendMFALoginCode delivers a fresh login code for a pending MFA
// challenge whose active method is email (or, once implemented, SMS) — a
// TOTP challenge needs no such call, since the user's authenticator app
// already has a valid code at all times. Called between Login returning
// MFARequired and the user submitting a code to VerifyMFALogin. method is
// optional: empty defaults to the account's highest-priority enabled
// method (LoginResult.MFAMethods[0]); given, it must be one of the
// account's actually-enabled methods (InvalidMFAMethod otherwise) — this
// is how a client asks for a specific one of several enabled methods
// instead of whatever this codebase's default priority would pick.
func SendMFALoginCode(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, resendClient *resend.Client, challengeToken, method string) *utils.ErrorDetail {
	userID, _, err := auth.VerifyAndParseTemporaryJWT(ctx, redisClient, "Bearer "+challengeToken, entities.RoleMFAPending)
	if err != nil {
		utils.LogDebug(ctx, "MFA login challenge token invalid or expired", zap.Error(err))
		return &utils.Errors.InvalidOrExpiredToken
	}
	userPG, ok := parseUserID(userID)
	if !ok {
		return &utils.Errors.Unauthorized
	}
	q := postgres.New(db)

	methods, mfaErr := listEnabledMFAMethods(ctx, q, userPG)
	if mfaErr != nil {
		utils.LogError(ctx, "listEnabledMFAMethods failed", zap.Error(mfaErr))
		return &utils.Errors.InternalServerError
	}
	if len(methods) == 0 {
		return &utils.Errors.MFANotEnabled
	}

	requested := strings.TrimSpace(method)
	switch {
	case requested == "":
		requested = methods[0]
	case !mfaMethodEnabled(methods, requested):
		return &utils.Errors.InvalidMFAMethod
	}

	switch requested {
	case "email":
		email, err := q.GetUserEmailByID(ctx, userPG)
		if err != nil {
			utils.LogError(ctx, "GetUserEmailByID failed", zap.Error(err))
			return &utils.Errors.InternalServerError
		}
		return sendMFAEmailCode(ctx, redisClient, resendClient, userID, email, "login")
	default:
		// TOTP (nothing to send) — calling this endpoint for it doesn't
		// make sense and isn't a real error condition the caller can act
		// on differently.
		return &utils.Errors.InvalidPayload
	}
}

// sendMFAEmailCode generates a fresh code, stores it in Redis scoped to
// (userID, purpose), and emails it — shared by enrollment and login-time
// sends. Rate-limited the same way as the signup verification code, so
// repeatedly hitting either endpoint can't be used to spam a user's inbox.
func sendMFAEmailCode(ctx context.Context, redisClient *redis.Client, resendClient *resend.Client, userID, email, purpose string) *utils.ErrorDetail {
	if existing, err := auth.GetMFAOTPCode(ctx, redisClient, "email", purpose, userID); err == nil && existing != nil {
		if time.Since(existing.CreatedAt) < mfaOTPRegenerateWindow {
			return &utils.Errors.TooSoonToRequest
		}
	}

	code := utils.GenerateCode()
	now := time.Now()
	meta := entities.OTPMeta{
		Code: code, CreatedAt: now, ExpiresAt: now.Add(config.Loaded.OTP_TTL),
		Attempts: 0, MaxAttempts: mfaOTPMaxAttempts,
	}
	if err := auth.SaveMFAOTPCode(ctx, redisClient, "email", purpose, userID, meta); err != nil {
		utils.LogError(ctx, "SaveMFAOTPCode failed", zap.Error(err))
		return &utils.Errors.InternalServerError
	}
	if _, err := emailer.SendEmailVerificationEmail(code, email, resendClient); err != nil {
		utils.LogError(ctx, "Failed to send MFA email code", zap.Error(err))
		return &utils.Errors.InternalServerError
	}
	return nil
}

// verifyMFAOTPCode checks a caller-supplied code against the pending
// email/SMS Redis-stored one for (channel, purpose, userID), applying the
// same expiry/attempt-limit/constant-time-comparison rules VerifyMFALogin
// applies to the login-time case — shared here so enrollment gets
// identical treatment rather than a slightly different reimplementation.
// factorID is used only to record a DB-side failed attempt.
func verifyMFAOTPCode(ctx context.Context, redisClient *redis.Client, q *postgres.Queries, channel, purpose, userID string, factorID pgtype.UUID, code string) *utils.ErrorDetail {
	meta, err := auth.GetMFAOTPCode(ctx, redisClient, channel, purpose, userID)
	if err != nil {
		return &utils.Errors.InvalidMFACode
	}
	if time.Now().After(meta.ExpiresAt) {
		return &utils.Errors.CodeExpired
	}
	if meta.Attempts >= meta.MaxAttempts {
		return &utils.Errors.TooManyAttempts
	}
	if !constantTimeEqual(strings.TrimSpace(code), meta.Code) {
		meta.Attempts++
		if err := auth.SaveMFAOTPCode(ctx, redisClient, channel, purpose, userID, *meta); err != nil {
			utils.LogWarn(ctx, "SaveMFAOTPCode failed", zap.Error(err))
		}
		if err := q.IncrementOTPFactorFailedAttempts(ctx, factorID); err != nil {
			utils.LogWarn(ctx, "IncrementOTPFactorFailedAttempts failed", zap.Error(err))
		}
		return &utils.Errors.InvalidMFACode
	}
	return nil
}
