package handlers

import (
	"net/http"

	"auth-api/internal/entities"
	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// PasskeyListHandler returns the authenticated user's registered passkeys
// (GET /auth/v1/passkey) — labels and timestamps only, never key material.
func (h *Handlers) PasskeyListHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing PasskeyListHandler flow")

	user, ok := ctx.Value(entities.UserContextKey).(*entities.UserContext)
	if !ok || user == nil {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}

	passkeys, err := services.ListPasskeys(ctx, h.Svcs.DB, user.ID)
	if err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.JSONResponse(w, http.StatusOK, map[string]any{"passkeys": passkeys})
}

// PasskeyRenameHandler updates a passkey's user-facing label (POST
// /auth/v1/passkey/:id/rename).
func (h *Handlers) PasskeyRenameHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing PasskeyRenameHandler flow")

	user, ok := ctx.Value(entities.UserContextKey).(*entities.UserContext)
	if !ok || user == nil {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}

	var payload struct {
		Name string `json:"name"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	if err := services.RenamePasskey(ctx, h.Svcs.DB, user.ID, ps.ByName("id"), payload.Name); err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "Passkey renamed."})
}

// PasskeyDeleteHandler removes a passkey (DELETE /auth/v1/passkey/:id).
// Requires the current password — see services.DeletePasskey.
func (h *Handlers) PasskeyDeleteHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing PasskeyDeleteHandler flow")

	user, ok := ctx.Value(entities.UserContextKey).(*entities.UserContext)
	if !ok || user == nil {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}

	var payload struct {
		CurrentPassword string `json:"current_password"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}

	if err := services.DeletePasskey(ctx, h.Svcs.DB, user.ID, payload.CurrentPassword, ps.ByName("id")); err != nil {
		utils.JSONError(w, *err)
		return
	}

	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "Passkey removed."})
}
