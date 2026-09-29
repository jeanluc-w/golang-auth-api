package handlers

import (
	"net/http"

	"auth-api/config"
	"auth-api/internal/auth"
	"auth-api/internal/db/postgres"
	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// SSOAppleHandler logs in (or, for a new email, signs up) via an Apple
// identity token (POST /auth/v1/sso/apple, an open route — the token
// itself is what's being authenticated). See services.SSOLogin for the
// verification and account-linking policy.
func (h *Handlers) SSOAppleHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing SSOAppleHandler flow")

	if h.Svcs.AppleJWKS == nil {
		utils.JSONError(w, utils.Errors.SSONotConfigured)
		return
	}

	var payload struct {
		IDToken string `json:"id_token"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	claims, err := auth.VerifyOIDCToken(payload.IDToken, h.Svcs.AppleJWKS, auth.AppleIssuer, config.Loaded.AppleClientID)
	if err != nil {
		utils.LogDebug(ctx, "Apple identity token verification failed")
		utils.JSONError(w, utils.Errors.SSOTokenInvalid)
		return
	}

	result, errDetail := services.SSOLogin(ctx, h.Svcs.DB, h.Svcs.RedisClient, postgres.ProviderNameApple, postgres.UserOriginApple, claims)
	if errDetail != nil {
		utils.JSONError(w, *errDetail)
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
