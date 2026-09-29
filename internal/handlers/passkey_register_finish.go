package handlers

import (
	"net/http"

	"auth-api/internal/entities"
	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// PasskeyRegisterFinishHandler completes passkey registration (POST
// /auth/v1/passkey/register/finish?name=<label>). The request body is the
// raw WebAuthn client response (navigator.credentials.create()'s result),
// not this API's usual JSON envelope — go-webauthn parses it directly from
// r.Body, byte-exact, so it's deliberately not pre-decoded here the way
// every other handler's payload is. name is optional and passed as a query
// parameter for the same reason: the body isn't available for it.
func (h *Handlers) PasskeyRegisterFinishHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing PasskeyRegisterFinishHandler flow")

	user, ok := ctx.Value(entities.UserContextKey).(*entities.UserContext)
	if !ok || user == nil {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}

	name := r.URL.Query().Get("name")
	if err := services.FinishPasskeyRegistration(ctx, h.Svcs.DB, h.Svcs.RedisClient, h.Svcs.WebAuthn, user.ID, user.Username, name, r); err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "Passkey registered."})
}
