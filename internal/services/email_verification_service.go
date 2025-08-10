package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"edibubble-api/internal/auth"
	"edibubble-api/internal/utils"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type VerificationResult struct {
	Token string
}

func VerifyEmailCode(ctx context.Context, redisClient *redis.Client, email string, code string) (*VerificationResult, *utils.ErrorDetail) {
	// Validate that the email is valid
	emailParsed := strings.ToLower(strings.TrimSpace(email))
	if !utils.IsValidEmail(emailParsed) {
		utils.LogDebug(ctx, "Invalid email format", zap.String("email", emailParsed))
		return nil, &utils.Errors.InvalidEmailFormat
	}

	// Validate the verification code
	codeParsed := strings.TrimSpace(code)
	if !utils.IsValidVerificationCode(codeParsed) {
		utils.LogDebug(ctx, "Invalid code")
		return nil, &utils.Errors.IncorrectCode
	}

	// Get the record from Redis
	meta, err := auth.GetVerificationCode(ctx, redisClient, emailParsed)
	if err != nil {
		utils.LogDebug(ctx, "Failed getting data from Redis", zap.Error(err))
		return nil, &utils.Errors.IncorrectCode
	}

	// Check expiration
	if time.Now().After(meta.ExpiresAt) {
		utils.LogDebug(ctx, "Verification code expired", zap.Time("expires_at", meta.ExpiresAt))
		return nil, &utils.Errors.CodeExpired
	}

	// Check max attempts
	if meta.Attempts >= meta.MaxAttempts {
		utils.LogDebug(ctx, "Too many attempts made", zap.Int("attempts", meta.Attempts), zap.Int("max_attempts", meta.MaxAttempts))
		return nil, &utils.Errors.TooManyAttempts
	}

	// Compare the verification codes
	if codeParsed != meta.Code {
		// Wrong code, increment failed attempts, store back in Redis, and return error
		meta.Attempts++
		err = auth.SaveVerificationCode(ctx, redisClient, emailParsed, *meta)
		if err != nil {
			utils.LogWarn(ctx, "Failed to update failed attempt in Redis", zap.Error(err))
		}
		utils.LogDebug(ctx, "Invalid verification code attempt", zap.String("email", emailParsed), zap.Int("attempts", meta.Attempts))
		return nil, &utils.Errors.IncorrectCode
	}

	// Attempt to generate a JWT for the user, return server error if it fails
	utils.LogInfo(ctx, "Email verification successful", zap.String("email", emailParsed))
	token, err := auth.GenerateTemporaryJWT(ctx, redisClient, emailParsed, 30*time.Minute)
	if err != nil {
		utils.LogError(ctx, "Failed to generate temporary JWT", zap.Error(err))
		return nil, &utils.Errors.InternalServerError
	}

	// Clear the verification code from Redis
	if err := redisClient.Del(ctx, fmt.Sprintf("email_code:%s", emailParsed)).Err(); err != nil {
		utils.LogWarn(ctx, "Failed to delete verification code from Redis", zap.Error(err))
	}

	utils.LogInfo(ctx, "Cleared Redis and generated JWT, returning response", zap.String("email", emailParsed))
	return &VerificationResult{Token: token}, nil
}
