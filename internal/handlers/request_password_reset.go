package handlers

import (
	"net/http"

	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// RequestPasswordResetHandler starts a password reset (POST
// /auth/v1/request-password-reset, an open route): it emails a reset token
// to the given address if it belongs to a usable account. The response is
// always the same generic success regardless of whether the account exists
// — see services.RequestPasswordReset for why.
func (h *Handlers) RequestPasswordResetHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing RequestPasswordResetHandler flow")

	var payload struct {
		Email string `json:"email"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	if err := services.RequestPasswordReset(ctx, h.Svcs.DB, h.Svcs.RedisClient, h.Svcs.ResendClient, payload.Email); err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.JSONResponse(w, http.StatusOK, map[string]string{
		"message": "If that email has an account, a password reset link has been sent",
	})
}
