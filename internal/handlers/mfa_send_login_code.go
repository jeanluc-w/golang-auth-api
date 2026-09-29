package handlers

import (
	"net/http"

	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// MFASendLoginCodeHandler delivers (or re-delivers, subject to a cooldown)
// a login code for an in-progress MFA challenge whose active method is
// email or SMS (POST /auth/v1/mfa/send-login-code, an open route — same
// reasoning as mfa/verify-login: the caller authenticates via the
// challenge token in the body, not a header, since there's no full session
// yet). Not needed, and refused, for a TOTP challenge — the user's
// authenticator app already has a valid code at all times. method is
// optional: omit it to use the account's default (highest-priority)
// enabled method, or name a specific one of several enabled methods
// instead — see services.SendMFALoginCode.
func (h *Handlers) MFASendLoginCodeHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing MFASendLoginCodeHandler flow")

	var payload struct {
		ChallengeToken string `json:"challenge_token"`
		Method         string `json:"method"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	if err := services.SendMFALoginCode(ctx, h.Svcs.DB, h.Svcs.RedisClient, h.Svcs.ResendClient, payload.ChallengeToken, payload.Method); err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "Code sent."})
}
