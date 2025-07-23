package handlers

import (
	"edibubble-api/config"
	"edibubble-api/internal/utils"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
)

func VerifyEmailCodeHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()

	var payload struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	emailParsed := strings.ToLower(strings.TrimSpace(payload.Email))

	meta, err := utils.GetVerificationCode(ctx, config.Loaded.RedisClient, emailParsed)
	if err != nil {
		utils.JSONError(w, http.StatusUnauthorized, "Invalid or expired code")
		return
	}

	// Check expiration
	if time.Now().After(meta.ExpiresAt) {
		utils.JSONError(w, http.StatusUnauthorized, "Code expired")
		return
	}

	// Check max attempts
	if meta.Attempts >= meta.MaxAttempts {
		utils.JSONError(w, http.StatusTooManyRequests, "Too many failed attempts")
		return
	}

	// Compare codes (case-insensitive)
	if strings.TrimSpace(payload.Code) != meta.Code {
		// Wrong code, increment attempts and store back
		meta.Attempts++
		_ = utils.SaveVerificationCode(ctx, config.Loaded.RedisClient, emailParsed, *meta)

		utils.JSONError(w, http.StatusUnauthorized, "Incorrect code")
		return
	}

	// Success — proceed and delete the Redis key
	_ = config.Loaded.RedisClient.Del(ctx, fmt.Sprintf("email_code:%s", emailParsed)).Err()

	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "Email verified"})
}
