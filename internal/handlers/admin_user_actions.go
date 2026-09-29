package handlers

import (
	"net/http"

	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

type adminReasonPayload struct {
	Reason string `json:"reason"`
}

// AdminBanUserHandler bans a user and revokes all of their sessions (POST
// /auth/v1/admin/users/:id/ban), moderator+.
func (h *Handlers) AdminBanUserHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing AdminBanUserHandler flow")

	actor, ok := adminUserFromContext(r)
	if !ok {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}
	var payload adminReasonPayload
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}
	if err := services.BanUser(ctx, h.Svcs.DB, h.Svcs.RedisClient, actor.ID, actor.Username, ps.ByName("id"), payload.Reason); err != nil {
		utils.JSONError(w, *err)
		return
	}
	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "User banned."})
}

// AdminUnbanUserHandler restores a banned account to active (POST
// /auth/v1/admin/users/:id/unban), moderator+.
func (h *Handlers) AdminUnbanUserHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing AdminUnbanUserHandler flow")

	actor, ok := adminUserFromContext(r)
	if !ok {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}
	var payload adminReasonPayload
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}
	if err := services.UnbanUser(ctx, h.Svcs.DB, h.Svcs.RedisClient, actor.ID, actor.Username, ps.ByName("id"), payload.Reason); err != nil {
		utils.JSONError(w, *err)
		return
	}
	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "User unbanned."})
}

// AdminDisableUserHandler disables a user and revokes all of their sessions
// (POST /auth/v1/admin/users/:id/disable), moderator+.
func (h *Handlers) AdminDisableUserHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing AdminDisableUserHandler flow")

	actor, ok := adminUserFromContext(r)
	if !ok {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}
	var payload adminReasonPayload
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}
	if err := services.DisableUser(ctx, h.Svcs.DB, h.Svcs.RedisClient, actor.ID, actor.Username, ps.ByName("id"), payload.Reason); err != nil {
		utils.JSONError(w, *err)
		return
	}
	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "User disabled."})
}

// AdminEnableUserHandler restores a disabled account to active (POST
// /auth/v1/admin/users/:id/enable), moderator+.
func (h *Handlers) AdminEnableUserHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing AdminEnableUserHandler flow")

	actor, ok := adminUserFromContext(r)
	if !ok {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}
	var payload adminReasonPayload
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}
	if err := services.EnableUser(ctx, h.Svcs.DB, h.Svcs.RedisClient, actor.ID, actor.Username, ps.ByName("id"), payload.Reason); err != nil {
		utils.JSONError(w, *err)
		return
	}
	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "User enabled."})
}

// AdminForceLogoutUserHandler revokes every session on an account without
// changing its status (POST /auth/v1/admin/users/:id/force-logout),
// moderator+.
func (h *Handlers) AdminForceLogoutUserHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing AdminForceLogoutUserHandler flow")

	actor, ok := adminUserFromContext(r)
	if !ok {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}
	var payload adminReasonPayload
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}
	if err := services.ForceLogoutUser(ctx, h.Svcs.DB, h.Svcs.RedisClient, actor.ID, actor.Username, ps.ByName("id"), payload.Reason); err != nil {
		utils.JSONError(w, *err)
		return
	}
	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "All sessions revoked."})
}

// AdminResetUserPasswordHandler sends a password-reset email to a user on
// an admin/moderator's behalf (POST
// /auth/v1/admin/users/:id/reset-password), moderator+.
func (h *Handlers) AdminResetUserPasswordHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing AdminResetUserPasswordHandler flow")

	actor, ok := adminUserFromContext(r)
	if !ok {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}
	if err := services.AdminResetUserPassword(ctx, h.Svcs.DB, h.Svcs.ResendClient, actor.ID, actor.Username, ps.ByName("id")); err != nil {
		utils.JSONError(w, *err)
		return
	}
	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "Password reset email sent."})
}

// AdminChangeUserRoleHandler promotes/demotes a user between 'user' and
// 'moderator' (POST /auth/v1/admin/users/:id/role), admin-only.
func (h *Handlers) AdminChangeUserRoleHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing AdminChangeUserRoleHandler flow")

	actor, ok := adminUserFromContext(r)
	if !ok {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}
	var payload struct {
		Role string `json:"role"`
	}
	if !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}
	if err := services.ChangeUserRole(ctx, h.Svcs.DB, actor.ID, actor.Username, ps.ByName("id"), payload.Role); err != nil {
		utils.JSONError(w, *err)
		return
	}
	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "Role updated."})
}

// AdminDeleteUserHandler soft-deletes an account and revokes all of their
// sessions (DELETE /auth/v1/admin/users/:id), admin-only.
func (h *Handlers) AdminDeleteUserHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing AdminDeleteUserHandler flow")

	actor, ok := adminUserFromContext(r)
	if !ok {
		utils.JSONError(w, utils.Errors.Unauthorized)
		return
	}
	var payload adminReasonPayload
	// DELETE requests may reasonably have no body; a decode failure here
	// (as opposed to simply no body) still gets treated as an invalid
	// payload for consistency with every other JSON-bodied write in this API.
	if r.ContentLength != 0 && !utils.DecodeJSONHandler(w, r, &payload) {
		return
	}
	if err := services.DeleteUser(ctx, h.Svcs.DB, h.Svcs.RedisClient, actor.ID, actor.Username, ps.ByName("id"), payload.Reason); err != nil {
		utils.JSONError(w, *err)
		return
	}
	utils.JSONResponse(w, http.StatusOK, map[string]string{"message": "User deleted."})
}
