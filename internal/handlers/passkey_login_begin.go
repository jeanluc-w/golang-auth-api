package handlers

import (
	"net/http"

	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// PasskeyLoginBeginHandler starts a usernameless passkey login (POST
// /auth/v1/passkey/login/begin, an open route). Returns WebAuthn assertion
// options plus a ceremony_id the client must send back to
// passkey/login/finish — see services.BeginPasskeyLogin.
func (h *Handlers) PasskeyLoginBeginHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing PasskeyLoginBeginHandler flow")

	challenge, err := services.BeginPasskeyLogin(ctx, h.Svcs.RedisClient, h.Svcs.WebAuthn)
	if err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.JSONResponse(w, http.StatusOK, challenge)
}
