package services

import (
	"context"
	"crypto/subtle"
	"errors"

	"auth-api/config"
	"auth-api/internal/auth"
	"auth-api/internal/db/postgres"
	"auth-api/internal/utils"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type RefreshTokenResult struct {
	AccessToken  string
	RefreshToken string
}

// RefreshToken rotates a session's access + refresh tokens.
//
// sessionID and userID come from the caller's most recent access JWT
// (parsed WITHOUT an expiration check by the JWT middleware, purely to
// identify the session) — they are not themselves proof of authentication.
// The actual proof is rawRefreshToken, which must hash to the value stored
// for that session in both Redis and Postgres.
//
// If the provided refresh token doesn't match what's on record, the session
// is revoked immediately rather than just rejected: a mismatch here means
// either the token was already rotated (this is a replay of an old,
// already-used token) or someone else has a stale copy of it, and in either
// case the safest response is to kill the session outright (this is the
// standard "refresh token reuse detection" mitigation).
func RefreshToken(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, sessionID, userID, rawRefreshToken string) (*RefreshTokenResult, *utils.ErrorDetail) {
	if sessionID == "" || userID == "" || rawRefreshToken == "" {
		return nil, &utils.Errors.Unauthorized
	}

	sessionUUID, err := uuid.Parse(sessionID)
	if err != nil {
		return nil, &utils.Errors.Unauthorized
	}
	sessionPG := pgtype.UUID{Bytes: sessionUUID, Valid: true}

	storedHash, err := redisClient.Get(ctx, "refresh:"+sessionID).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			utils.LogError(ctx, "Redis GET failed during refresh", zap.Error(err))
			return nil, &utils.Errors.InternalServerError
		}
		// Key genuinely missing: never existed, already expired, or was
		// already consumed/revoked.
		return nil, &utils.Errors.SessionExpired
	}

	suppliedHash := auth.HashRefreshToken(rawRefreshToken)
	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(suppliedHash)) != 1 {
		revokeCompromisedSession(ctx, db, redisClient, sessionID, sessionPG)
		utils.LogWarn(ctx, "Refresh token mismatch; session revoked", zap.String("session_id", sessionID))
		return nil, &utils.Errors.SessionExpired
	}

	q := postgres.New(db)
	session, err := q.GetRefreshSession(ctx, sessionPG)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			utils.LogError(ctx, "GetRefreshSession failed", zap.Error(err))
			return nil, &utils.Errors.InternalServerError
		}
		return nil, &utils.Errors.SessionExpired
	}

	if session.Revoked.Bool || session.UserID.String() != userID ||
		subtle.ConstantTimeCompare([]byte(session.RefreshTokenHash.String), []byte(suppliedHash)) != 1 {
		revokeCompromisedSession(ctx, db, redisClient, sessionID, sessionPG)
		utils.LogWarn(ctx, "Refresh session invalid or mismatched; revoked", zap.String("session_id", sessionID))
		return nil, &utils.Errors.SessionExpired
	}

	user, err := q.GetUserByID(ctx, session.UserID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			utils.LogError(ctx, "GetUserByID failed during refresh", zap.Error(err))
			return nil, &utils.Errors.InternalServerError
		}
		revokeCompromisedSession(ctx, db, redisClient, sessionID, sessionPG)
		return nil, &utils.Errors.Unauthorized
	}
	if user.DeletedAt.Valid || (user.Status.Valid && (user.Status.UserStatus == postgres.UserStatusBanned || user.Status.UserStatus == postgres.UserStatusDisabled)) {
		revokeCompromisedSession(ctx, db, redisClient, sessionID, sessionPG)
		return nil, &utils.Errors.AccountNotUsable
	}

	tokens, err := auth.RotateSessionTokens(
		ctx,
		redisClient,
		sessionID,
		session.UserID.String(),
		user.Username,
		string(user.Role),
		config.Loaded.AccessTTL,
		config.Loaded.RefreshTTL,
	)
	if err != nil {
		utils.LogError(ctx, "Failed to rotate tokens during refresh", zap.Error(err))
		return nil, &utils.Errors.TokenGenerationFailed
	}

	newHash := auth.HashRefreshToken(tokens.RefreshToken)
	if _, err := q.RotateRefreshSession(ctx, postgres.RotateRefreshSessionParams{
		RefreshTokenHash: pgtype.Text{String: newHash, Valid: true},
		ExpiresAt:        pgtype.Timestamptz{Time: tokens.RefreshExp, Valid: true},
		ID:               sessionPG,
	}); err != nil {
		utils.LogError(ctx, "RotateRefreshSession failed", zap.Error(err))
		return nil, &utils.Errors.TokenGenerationFailed
	}

	return &RefreshTokenResult{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func revokeCompromisedSession(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, sessionID string, sessionPG pgtype.UUID) {
	_ = auth.DeleteSession(ctx, sessionID, redisClient)
	if err := postgres.New(db).RevokeSession(ctx, sessionPG); err != nil {
		utils.LogError(ctx, "Failed to revoke compromised session", zap.Error(err), zap.String("session_id", sessionID))
	}
}
