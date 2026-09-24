package handlers

import (
	"net/http"

	"auth-api/internal/entities"
	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// LogoutHandler revokes the caller's current session (POST /auth/v1/logout).
// Requires a valid access token; the session it revokes is whichever one
// that token belongs to.
func (h *Handlers) LogoutHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing LogoutHandler flow")

	user, ok := ctx.Value(entities.UserContextKey).(*entities.UserContext)
	if !ok || user == nil {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}

	if err := services.Logout(ctx, h.Svcs.DB, h.Svcs.RedisClient, user.SessionID); err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "Logged out"})
}
