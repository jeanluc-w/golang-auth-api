package handlers

import (
	"net/http"

	"auth-api/internal/entities"
	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// PasskeyRegisterBeginHandler starts adding a passkey to the authenticated
// account (POST /auth/v1/passkey/register/begin). Returns WebAuthn
// creation options for the client to pass directly to
// navigator.credentials.create().
func (h *Handlers) PasskeyRegisterBeginHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing PasskeyRegisterBeginHandler flow")

	user, ok := ctx.Value(entities.UserContextKey).(*entities.UserContext)
	if !ok || user == nil {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}

	options, err := services.BeginPasskeyRegistration(ctx, h.Svcs.DB, h.Svcs.RedisClient, h.Svcs.WebAuthn, user.ID, user.Username)
	if err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.JSONResponse(w, http.StatusOK, options)
}
