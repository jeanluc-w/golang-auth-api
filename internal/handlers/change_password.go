package handlers

import (
	"net/http"

	"auth-api/internal/entities"
	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// ChangePasswordHandler lets an authenticated user change their password
// (POST /auth/v1/change-password). Requires a valid access token and the
// current password; every other session on the account is revoked on
// success, but not the one making this request. See services.ChangePassword.
func (h *Handlers) ChangePasswordHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing ChangePasswordHandler flow")

	user, ok := ctx.Value(entities.UserContextKey).(*entities.UserContext)
	if !ok || user == nil {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}

	var payload struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	if err := services.ChangePassword(ctx, h.Svcs.DB, h.Svcs.RedisClient, user.ID, user.SessionID, payload.CurrentPassword, payload.NewPassword, payload.ConfirmPassword); err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.JSONResponse(w, http.StatusOK, map[string]string{
		"message": "Password changed successfully. You've been logged out of all other sessions.",
	})
}
