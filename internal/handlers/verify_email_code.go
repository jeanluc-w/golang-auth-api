package handlers

import (
	"edibubble-api/config"
	"edibubble-api/internal/auth"
	"edibubble-api/internal/utils"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"
)

func VerifyEmailCodeHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing VerifyEmailCodeHandler flow")

	// Decode the JSON payload
	var payload struct {
		Code  string `json:"code"`
		Email string `json:"email"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	// Validate the email
	emailParsed := strings.ToLower(strings.TrimSpace(payload.Email))
	if !utils.IsValidEmail(emailParsed) {
		utils.LogDebug(ctx, "Invalid email format", zap.String("email", emailParsed))
		utils.JSONError(w, http.StatusBadRequest, utils.Errors.InvalidEmailFormat)
		return
	}

	// Validate the verification code
	if !utils.IsValidVerificationCode(payload.Code) {
		utils.LogDebug(ctx, "Invalid code")
		utils.JSONError(w, http.StatusBadRequest, utils.Errors.IncorrectCode)
		return
	}

	// Get the record from Redis
	meta, err := auth.GetVerificationCode(ctx, config.Loaded.RedisClient, emailParsed)
	if err != nil {
		utils.LogDebug(ctx, "Failed getting data from Redis", zap.Error(err))
		utils.JSONError(w, http.StatusUnauthorized, utils.Errors.IncorrectCode)
		return
	}

	// Check expiration
	if time.Now().After(meta.ExpiresAt) {
		utils.LogDebug(ctx, "Verification code expired", zap.Time("expires_at", meta.ExpiresAt))
		utils.JSONError(w, http.StatusUnauthorized, utils.Errors.CodeExpired)
		return
	}

	// Check max attempts
	if meta.Attempts >= meta.MaxAttempts {
		utils.LogDebug(ctx, "Too many attempts made", zap.Int("attempts", meta.Attempts), zap.Int("max_attempts", meta.MaxAttempts))
		utils.JSONError(w, http.StatusTooManyRequests, utils.Errors.TooManyAttempts)
		return
	}

	// Compare the verification codes
	if strings.TrimSpace(payload.Code) != meta.Code {
		// Wrong code, increment failed attempts, store back in Redis, and return error
		meta.Attempts++
		err = auth.SaveVerificationCode(ctx, config.Loaded.RedisClient, emailParsed, *meta)
		if err != nil {
			utils.LogWarn(ctx, "Failed to update failed attempt in Redis", zap.Error(err))
		}
		utils.LogDebug(ctx, "Invalid verification code attempt", zap.String("email", emailParsed), zap.Int("attempts", meta.Attempts))
		utils.JSONError(w, http.StatusUnauthorized, utils.Errors.IncorrectCode)
		return
	}

	// Attempt to generate a JWT for the user, return server error if it fails
	utils.LogInfo(ctx, "Email verification successful", zap.String("email", emailParsed))
	token, err := auth.GenerateTemporaryJWT(emailParsed, 30*time.Minute)
	if err != nil {
		utils.LogError(ctx, "Failed to generate temporary JWT", zap.Error(err))
		utils.JSONError(w, http.StatusInternalServerError, utils.Errors.InternalServerError)
		return
	}

	// Clear the verification code from Redis
	if err := config.Loaded.RedisClient.Del(ctx, fmt.Sprintf("email_code:%s", emailParsed)).Err(); err != nil {
		utils.LogWarn(ctx, "Failed to delete verification code from Redis", zap.Error(err))
	}
	utils.LogInfo(ctx, "Cleared Redis and generated JWT, returning response", zap.String("email", emailParsed))
	utils.JSONResponse(w, http.StatusOK, map[string]any{
		"message": "Email verified",
		"token":   token,
	})
}
