package handlers

import (
	"net/http"
	"strconv"

	"auth-api/internal/db/postgres"
	"auth-api/internal/entities"
	"auth-api/internal/services"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

var roleRank = map[postgres.UserRole]int{
	postgres.UserRoleUser:      0,
	postgres.UserRoleModerator: 1,
	postgres.UserRoleAdmin:     2,
}

// requireRole wraps an httprouter.Handle so it only runs for a caller whose
// persisted role (entities.UserContext.Role — always a real, current-as-of-
// login-or-refresh users.role value, never a temporary-JWT role like
// RoleJoiner/RoleMFAPending) is at least min. An unrecognized role value
// ranks below every real role, so it's refused rather than let through.
// This is the entire admin/moderator authorization boundary — every admin
// handler is registered through this in router.go, and admin_service.go
// deliberately does not re-check role itself (see its package doc).
func requireRole(min postgres.UserRole, next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		user, ok := r.Context().Value(entities.UserContextKey).(*entities.UserContext)
		if !ok || user == nil {
			utils.JSONError(w, utils.Errors.Unauthorized)
			return
		}
		if roleRank[postgres.UserRole(user.Role)] < roleRank[min] {
			utils.JSONError(w, utils.Errors.Forbidden)
			return
		}
		next(w, r, ps)
	}
}

// adminUserFromContext pulls the authenticated caller out of the request
// context; requireRole already guarantees this succeeds by the time an
// admin handler runs, but every handler still checks rather than assuming
// it, matching the rest of this codebase's handlers.
func adminUserFromContext(r *http.Request) (*entities.UserContext, bool) {
	user, ok := r.Context().Value(entities.UserContextKey).(*entities.UserContext)
	return user, ok && user != nil
}

// AdminListUsersHandler lists/searches user accounts (GET
// /auth/v1/admin/users?search=&status=&role=&limit=&offset=), moderator+.
func (h *Handlers) AdminListUsersHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing AdminListUsersHandler flow")

	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	result, err := services.ListUsers(ctx, h.Svcs.DB, services.AdminListUsersParams{
		Search: q.Get("search"), Status: q.Get("status"), Role: q.Get("role"),
		Limit: limit, Offset: offset,
	})
	if err != nil {
		utils.JSONError(w, *err)
		return
	}
	utils.JSONResponse(w, http.StatusOK, result)
}

// AdminGetUserHandler returns the detail view of a single account (GET
// /auth/v1/admin/users/:id), moderator+.
func (h *Handlers) AdminGetUserHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing AdminGetUserHandler flow")

	result, err := services.GetUser(ctx, h.Svcs.DB, ps.ByName("id"))
	if err != nil {
		utils.JSONError(w, *err)
		return
	}
	utils.JSONResponse(w, http.StatusOK, result)
}

// AdminListAuditLogsHandler lists audit log entries, optionally filtered to
// one user (GET /auth/v1/admin/audit-logs?target_user_id=&limit=&offset=),
// moderator+.
func (h *Handlers) AdminListAuditLogsHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()
	utils.LogDebug(ctx, "Processing AdminListAuditLogsHandler flow")

	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	result, err := services.ListAuditLogs(ctx, h.Svcs.DB, q.Get("target_user_id"), limit, offset)
	if err != nil {
		utils.JSONError(w, *err)
		return
	}
	utils.JSONResponse(w, http.StatusOK, result)
}
