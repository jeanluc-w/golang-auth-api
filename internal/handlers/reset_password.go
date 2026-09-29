package handlers

import (
	"net/http"

	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// ResetPasswordHandler completes a password reset (POST
// /auth/v1/reset-password, an open route — the token itself, not a session,
// is what authenticates this request): given the token emailed by
// RequestPasswordResetHandler plus a new password, it updates the password
// and revokes every existing session on the account.
func (h *Handlers) ResetPasswordHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing ResetPasswordHandler flow")

	var payload struct {
		Token           string `json:"token"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	if err := services.ResetPassword(ctx, h.Svcs.DB, h.Svcs.RedisClient, payload.Token, payload.NewPassword, payload.ConfirmPassword); err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.JSONResponse(w, http.StatusOK, map[string]string{
		"message": "Password reset successfully. Please log in again.",
	})
}
