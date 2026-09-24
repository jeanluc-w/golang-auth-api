package services

import (
	"context"

	"auth-api/internal/auth"
	"auth-api/internal/db/postgres"
	"auth-api/internal/utils"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// Logout revokes the caller's current session: it's removed from Redis
// immediately (so the access token stops working right away, even though it
// hasn't expired yet) and marked revoked in Postgres (so a stale copy of
// the refresh token can't be used either).
func Logout(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, sessionID string) *utils.ErrorDetail {
	if sessionID == "" {
		return &utils.Errors.Unauthorized
	}

	sessionUUID, err := uuid.Parse(sessionID)
	if err != nil {
		return &utils.Errors.Unauthorized
	}

	if err := auth.DeleteSession(ctx, sessionID, redisClient); err != nil {
		utils.LogWarn(ctx, "Failed to delete session from redis on logout", zap.Error(err))
	}

	if err := postgres.New(db).RevokeSession(ctx, pgtype.UUID{Bytes: sessionUUID, Valid: true}); err != nil {
		utils.LogError(ctx, "Failed to revoke session in db on logout", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	utils.LogInfo(ctx, "Logout successful", zap.String("session_id", sessionID))
	return nil
}
