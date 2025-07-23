package handlers

import (
	"edibubble-api/config"
	"edibubble-api/internal/email"
	"edibubble-api/internal/models"
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

	// Validate that the email isn't already registered
	emailParsed := strings.ToLower(strings.TrimSpace(payload.Email))
	if !utils.IsValidEmail(emailParsed) {
		utils.JSONError(w, http.StatusBadRequest, "Invalid email format")
		return
	}

	// Check if the email was generated recently
	const regenerateWindow = 5 * time.Minute
	meta, err := utils.GetVerificationCode(ctx, config.Loaded.RedisClient, emailParsed)
	if err == nil && meta != nil {
		now := time.Now()

		// Check if it's too early to regenerate another code
		if now.Before(meta.ExpiresAt) && now.Add(regenerateWindow).Before(meta.ExpiresAt) && meta.Attempts < meta.MaxAttempts {
			utils.JSONError(w, http.StatusTooManyRequests, "Verification already requested")
			return
		}
	}

	// Create a unique code and store it in Redis
	utils.LogInfo(ctx, "Generating verification code for email", zap.String("email", emailParsed))
	code := utils.GenerateCode()
	otpMeta := models.OTPMeta{
		Code:        code,
		ExpiresAt:   time.Now().Add(config.Loaded.OTP_TTL * time.Minute),
		Attempts:    0,
		MaxAttempts: 5,
	}

	// Save the code to Redis DB
	utils.LogInfo(ctx, "Generated verification code, saving to Redis")
	if err := utils.SaveVerificationCode(ctx, config.Loaded.RedisClient, emailParsed, otpMeta); err != nil {
		utils.LogError(ctx, "Failed to save verification code", zap.Error(err))
		utils.JSONError(w, http.StatusInternalServerError, "Failed to store code")
		return
	}

	// Send the email with the code through Resend.
	utils.LogInfo(ctx, "Saved code to Redis, sending verification email", zap.String("email", emailParsed))
	if err := email.SendEmailVerificationEmail(code, emailParsed); err != nil {
		utils.LogError(ctx, "Failed to send verification email")
		utils.JSONError(w, http.StatusInternalServerError, "Failed to send verification email")
		return
	}

	// Respond with success
	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "Verification code sent"})
}
