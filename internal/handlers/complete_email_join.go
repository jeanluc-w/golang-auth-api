package handlers

import (
	"edibubble-api/internal/models"
	"edibubble-api/internal/utils"
	"net/http"

	"go.uber.org/zap"
)

func CompleteEmailJoinHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Starting CompleteEmailJoinHandler")

	email := utils.GetContextString(r, models.EmailFromDecodedTempJWTKey, "")

	// Validate the email again just to make sure it's allowed in case of weird
	// JWT exploits ocurred
	if email == "" || !utils.IsValidEmail(email) {
		utils.LogError(ctx, "Email pulled from context failed to pass validation", zap.String("email_parsed", email))
		utils.JSONError(w, http.StatusUnauthorized, utils.Errors.Unauthorized)
	}

	// Decode the payload
	var payload struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	// Validate the payload

}
