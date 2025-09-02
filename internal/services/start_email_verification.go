package services

import (
	"context"
	"edibubble-api/config"
	"edibubble-api/internal/auth"
	"edibubble-api/internal/emailer"
	"edibubble-api/internal/entities"
	"edibubble-api/internal/utils"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/resend/resend-go/v2"
	"go.uber.org/zap"
)

func StartEmailVerification(ctx context.Context, db *pgxpool.Pool, redisClient *redis.Client, resendClient *resend.Client, email string) *utils.ErrorDetail {
	// Validate that the email is valid
	emailParsed := strings.ToLower(strings.TrimSpace(email))
	if !utils.IsValidEmail(emailParsed) {
		utils.LogDebug(ctx, "Invalid email format", zap.String("email", emailParsed))
		return &utils.Errors.InvalidEmailFormat
	}

	// Validate that the user's email doesn't already exist in the auth table
	taken, err := auth.IsEmailTaken(ctx, emailParsed, db)
	if err != nil {
		utils.LogError(ctx, "Failed to check if email is taken", zap.Error(err))
		return &utils.Errors.InternalServerError
	}
	if taken == true {
		utils.LogInfo(ctx, "Email is already associated with an account", zap.String("email", emailParsed))
		return &utils.Errors.EmailIsTaken
	}

	// Check if the email was generated recently (within the past minute)
	const regenerateWindow = 1 * time.Minute
	meta, err := auth.GetVerificationCode(ctx, redisClient, emailParsed)
	if err == nil && meta != nil {
		now := time.Now()

		// Check if it's too early to regenerate another code
		if now.Sub(meta.CreatedAt) < regenerateWindow {
			utils.LogDebug(ctx, "Too early to regenerate code", zap.String("email", emailParsed), zap.Duration("wait_time", regenerateWindow-now.Sub(meta.CreatedAt)))
			return &utils.Errors.TooManyAttempts
		}
	}

	// Create a unique code and store it in Redis
	utils.LogInfo(ctx, "Generating verification code for email", zap.String("email", emailParsed))
	code := utils.GenerateCode()
	currentTime := time.Now()
	otpMeta := entities.OTPMeta{
		Code:        code,
		CreatedAt:   currentTime,
		ExpiresAt:   currentTime.Add(config.Loaded.OTP_TTL),
		Attempts:    0,
		MaxAttempts: 5,
	}

	// Save the code to Redis DB
	utils.LogInfo(ctx, "Generated verification code, saving to Redis")
	if err := auth.SaveVerificationCode(ctx, redisClient, emailParsed, otpMeta); err != nil {
		utils.LogError(ctx, "Failed to save verification code", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	// Send the email with the code through Resend.
	utils.LogInfo(ctx, "Saved code to Redis, sending verification email", zap.String("email", emailParsed))
	id, err := emailer.SendEmailVerificationEmail(code, emailParsed, resendClient)
	if err != nil {
		utils.LogError(ctx, "Failed to send verification email", zap.Error(err))
		return &utils.Errors.InternalServerError
	}

	// Respond with success
	utils.LogInfo(ctx, "Verification email sent successfully", zap.String("email", emailParsed), zap.String("email_id", id))
	return nil
}
