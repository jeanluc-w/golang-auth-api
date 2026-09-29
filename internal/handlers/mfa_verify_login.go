package handlers

import (
	"net/http"

	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// MFAVerifyLoginHandler completes an MFA-gated login (POST
// /auth/v1/mfa/verify-login, an open route — see server.OpenRoutes'
// comment on why). Given the challenge token from LoginHandler's
// mfa_required response plus a code, it returns a normal access + refresh
// token pair exactly like LoginHandler would have without MFA in the way.
// method is optional: omit it to have every enabled method tried against
// the code in this codebase's default priority order, or name a specific
// one to check only that method's code (a recovery code always works
// either way) — see services.VerifyMFALogin.
func (h *Handlers) MFAVerifyLoginHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing MFAVerifyLoginHandler flow")

	var payload struct {
		ChallengeToken string `json:"challenge_token"`
		Method         string `json:"method"`
		Code           string `json:"code"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	result, err := services.VerifyMFALogin(ctx, h.Svcs.DB, h.Svcs.RedisClient, payload.ChallengeToken, payload.Method, payload.Code)
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
