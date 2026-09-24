package handlers

import (
	"net/http"

	"auth-api/internal/entities"
	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// RefreshTokenHandler rotates a session's tokens (POST /auth/v1/refresh-token).
// The caller's most recent access token (expired or not) identifies the
// session via the Authorization header; the request body's refresh_token
// is what actually authenticates the request. See services.RefreshToken for
// the reuse-detection behavior.
func (h *Handlers) RefreshTokenHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing RefreshTokenHandler flow")

	var payload struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	sessionID := utils.GetContextString(ctx, entities.SessionIDFromExpiredJWTContextKey, "")
	userID := utils.GetContextString(ctx, entities.UserIDFromExpiredJWTContextKey, "")

	result, err := services.RefreshToken(ctx, h.Svcs.DB, h.Svcs.RedisClient, sessionID, userID, payload.RefreshToken)
	if err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.JSONResponse(w, http.StatusOK, map[string]any{
		"message":       "Token refreshed",
		"token":         result.AccessToken,
		"refresh_token": result.RefreshToken,
	})
}
