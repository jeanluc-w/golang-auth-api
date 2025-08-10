package handlers

import (
	"edibubble-api/internal/services"
	"edibubble-api/internal/utils"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"
)

func (h *Handlers) CompleteEmailJoinHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Starting CompleteEmailJoinHandler")

	// Decode the payload
	var payload struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	// Complete the service request
	result, err := services.CompleteEmailJoin(
		ctx,
		h.Svcs.DB,
		h.Svcs.RedisClient,
		payload.Username,
		payload.Password,
		payload.ConfirmPassword,
	)

	// Return an error response if it failed
	if err != nil {
		utils.JSONError(w, *err)
		return
	}

	// Return the user's token on success
	utils.LogInfo(ctx, "Account created successfully", zap.String("username", result.Username))
	utils.JSONResponse(w, http.StatusCreated, map[string]any{
		"message":       "Account created successfully",
		"token":         result.AccessToken,
		"refresh_token": result.RefreshToken,
		"user": map[string]any{
			"id":       result.UserID,
			"username": result.Username,
		},
	})
}
