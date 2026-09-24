package handlers

import (
	"net/http"

	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"
)

// LoginHandler authenticates an email/password pair (POST /auth/v1/login,
// an open route) and returns a new access + refresh token pair. See
// services.Login for the lockout and timing-safety behavior.
func (h *Handlers) LoginHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing LoginHandler flow")

	var payload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	result, err := services.Login(ctx, h.Svcs.DB, h.Svcs.RedisClient, payload.Email, payload.Password)
	if err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.LogInfo(ctx, "Login succeeded", zap.String("user_id", result.UserID))
	utils.JSONResponse(w, http.StatusOK, map[string]any{
		"message":       "Login successful",
		"token":         result.AccessToken,
		"refresh_token": result.RefreshToken,
		"user": map[string]any{
			"id":       result.UserID,
			"username": result.Username,
		},
	})
}
