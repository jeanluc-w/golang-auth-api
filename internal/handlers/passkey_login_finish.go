package handlers

import (
	"net/http"

	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// PasskeyLoginFinishHandler completes a passkey login (POST
// /auth/v1/passkey/login/finish?ceremony_id=<id>, an open route — the
// caller doesn't have a session yet, that's the point). The request body
// is the raw WebAuthn client response, not this API's usual JSON envelope
// — see PasskeyRegisterFinishHandler's comment for why. On success this
// bypasses any separate TOTP/email MFA gate and returns real tokens
// directly; see services.FinishPasskeyLogin's doc comment for why.
func (h *Handlers) PasskeyLoginFinishHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing PasskeyLoginFinishHandler flow")

	ceremonyID := r.URL.Query().Get("ceremony_id")
	result, err := services.FinishPasskeyLogin(ctx, h.Svcs.DB, h.Svcs.RedisClient, h.Svcs.WebAuthn, ceremonyID, r)
	if err != nil {
		utils.JSONError(w, *err)
		return
	}

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
