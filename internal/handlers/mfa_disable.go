package handlers

import (
	"net/http"

	"auth-api/internal/entities"
	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// MFADisableHandler turns off MFA for the authenticated user (POST
// /auth/v1/mfa/disable). Requires the current password as
// re-authentication — see services.DisableMFA.
func (h *Handlers) MFADisableHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing MFADisableHandler flow")

	user, ok := ctx.Value(entities.UserContextKey).(*entities.UserContext)
	if !ok || user == nil {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}

	var payload struct {
		CurrentPassword string `json:"current_password"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	if err := services.DisableMFA(ctx, h.Svcs.DB, user.ID, payload.CurrentPassword); err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "MFA disabled"})
}
