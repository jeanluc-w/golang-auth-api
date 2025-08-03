package handlers

import (
	"edibubble-api/config"
	"edibubble-api/internal/auth"
	"edibubble-api/internal/email"
	"edibubble-api/internal/entities"
	"edibubble-api/internal/utils"
	"net/http"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"
)

func StartEmailVerificationHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing StartEmailVerificationHandler flow")

	// Decode the JSON payload
	var payload struct {
		Email string `json:"email"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	// Validate that the email is valid
	emailParsed := strings.ToLower(strings.TrimSpace(payload.Email))
	if !utils.IsValidEmail(emailParsed) {
		utils.LogDebug(ctx, "Invalid email format", zap.String("email", emailParsed))
		utils.JSONError(w, http.StatusBadRequest, utils.Errors.InvalidEmailFormat)
		return
	}

	// TODO: Add validation that the user doesn't already exist in the DB

	// Check if the email was generated recently (within the past minute)
	const regenerateWindow = 1 * time.Minute
	meta, err := auth.GetVerificationCode(ctx, config.Loaded.RedisClient, emailParsed)
	if err == nil && meta != nil {
		now := time.Now()

		// Check if it's too early to regenerate another code
		if now.Sub(meta.CreatedAt) < regenerateWindow {
			utils.LogDebug(ctx, "Too early to regenerate code", zap.String("email", emailParsed), zap.Duration("wait_time", regenerateWindow-now.Sub(meta.CreatedAt)))
			utils.JSONError(w, http.StatusTooManyRequests, utils.Errors.TooManyAttempts)
			return
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
	if err := auth.SaveVerificationCode(ctx, config.Loaded.RedisClient, emailParsed, otpMeta); err != nil {
		utils.LogError(ctx, "Failed to save verification code", zap.Error(err))
		utils.JSONError(w, http.StatusInternalServerError, utils.Errors.InternalServerError)
		return
	}

	// Send the email with the code through Resend.
	utils.LogInfo(ctx, "Saved code to Redis, sending verification email", zap.String("email", emailParsed))
	id, err := email.SendEmailVerificationEmail(code, emailParsed)
	if err != nil {
		utils.LogError(ctx, "Failed to send verification email", zap.Error(err))
		utils.JSONError(w, http.StatusInternalServerError, utils.Errors.InternalServerError)
		return
	}

	// Respond with success
	utils.LogInfo(ctx, "Verification email sent successfully", zap.String("email", emailParsed), zap.String("email_id", id))
	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "Verification code sent"})
}
