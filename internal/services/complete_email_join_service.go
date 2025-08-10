package services

import (
	"context"
	"edibubble-api/config"
	"edibubble-api/internal/auth"
	"edibubble-api/internal/db/postgres"
	"edibubble-api/internal/entities"
	"edibubble-api/internal/utils"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type EmailJoinResult struct {
	AccessToken  string
	RefreshToken string
	UserID       string
	Username     string
}

func CompleteEmailJoin(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, username string, password string, confirmPassword string) (*EmailJoinResult, *utils.ErrorDetail) {
	email := utils.GetContextString(ctx, entities.EmailFromDecodedTempJWTContextKey, "")
	// Validate the email again just to make sure it's allowed just in case
	if email == "" || !utils.IsValidEmail(email) {
		utils.LogError(ctx, "Email pulled from context failed to pass validation", zap.String("email_parsed", email))
		return nil, &utils.Errors.Unauthorized
	}

	// Check that username is valid
	if !utils.IsValidUsername(username) {
		utils.LogInfo(ctx, "Username failed validation")
		return nil, &utils.Errors.InvalidUsernameFormat
	}

	// Check that the password is valid
	if !utils.IsValidPassword(password) {
		utils.LogInfo(ctx, "Password is invalid length")
		return nil, &utils.Errors.InvalidPasswordFormat
	}

	// Check that the password matches the confirm password
	if password != confirmPassword {
		utils.LogInfo(ctx, "Passwords don't match")
		return nil, &utils.Errors.InvalidPasswordFormat
	}

	// Check if username is already taken
	taken, err := postgres.New(db).UsernameExists(ctx, username)
	if err != nil {
		utils.LogError(ctx, "UsernameExists check failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}
	if taken {
		utils.LogInfo(ctx, "Username already taken")
		return nil, &utils.Errors.UsernameTaken
	}

	// Hash the password to be saved in the DB.
	passwordHash, err := auth.HashPasswordPHC(password)
	if err != nil {
		utils.LogError(ctx, "Hashing failed", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	// Generate the user in the DB
	user, err := postgres.CreateEmailUser(ctx, db, email, username, passwordHash)
	if err != nil {
		utils.LogError(ctx, "Failed to generate the user and auth identity in the database", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	// Delete the temporary JWT's session
	if err := auth.DeleteTemporarySession(ctx, utils.GetContextString(ctx, entities.JTIFromDecodedTempJWTContextKey, ""), redisClient); err != nil {
		utils.LogWarn(ctx, "Failed to delete the temp JWT's session", zap.Error(err))
	}

	// Generate the session in Redis and JWT token + refresh token for the new user
	tokens, err := auth.GenerateUserTokens(
		ctx,
		redisClient,
		user.ID.String(),
		user.Username,
		string(user.Role),
		config.Loaded.AccessTTL,
		config.Loaded.RefreshTTL,
	)
	if err != nil {
		utils.LogError(ctx, "Failed to generate new user's tokens + sessions", zap.Error(err))
		return nil, &utils.Errors.TokenGenerationFailed
	}

	// Store the Refresh token in the DB as well
	// TODO fix the refresh token storage and redis deletion flow
	q := postgres.New(db)
	refreshHash := auth.HashRefreshToken(tokens.RefreshToken)
	_, err = postgres.CreateRefreshSession(ctx, q, postgres.RefreshSessionInput{
		SessionID:        tokens.SessionID,
		UserID:           user.ID,
		ExpiresAt:        tokens.RefreshExp,
		RefreshTokenHash: refreshHash,
		IP:               utils.ClientIPFromCtx(ctx),
		UserAgent:        utils.UserAgentFromCtx(ctx),
	})
	if err != nil {
		// Roll back Redis refresh key so we don't leave a dangling session
		_ = redisClient.Del(ctx, "refresh:"+tokens.SessionID).Err()
		utils.LogError(ctx, "CreateRefreshSession failed", zap.Error(err))
		return nil, &utils.Errors.TokenGenerationFailed
	}

	return &EmailJoinResult{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		UserID:       user.ID.String(),
		Username:     user.Username,
	}, nil
}
