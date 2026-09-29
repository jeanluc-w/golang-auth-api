package handlers

import (
	"net/http"

	"auth-api/internal/db/postgres"
	"auth-api/internal/server"
	"auth-api/internal/utils"

	"github.com/julienschmidt/httprouter"
)

// NewHandler builds the complete application HTTP handler: route
// registration plus the full middleware stack (BuildHandlerStack). Used by
// both cmd/main.go and the integration test suite (test/integration), so
// route registration can never silently drift between what's deployed and
// what's tested.
func NewHandler(svcs *server.Services) http.Handler {
	h := New(svcs)
	router := httprouter.New()

	// Health Check API
	router.GET(server.V1_HealthCheck, h.HealthCheckHandler)
	// Email Join APIs
	router.POST(server.V1_StartEmailVerification, h.StartEmailVerificationHandler)
	router.POST(server.V1_VerifyEmail, h.VerifyEmailCodeHandler)
	router.POST(server.V1_CompleteEmailJoin, h.CompleteEmailJoinHandler)
	// Session APIs
	router.POST(server.V1_Login, h.LoginHandler)
	router.POST(server.V1_Logout, h.LogoutHandler)
	router.POST(server.V1_RefreshToken, h.RefreshTokenHandler)
	// Password reset / change APIs
	router.POST(server.V1_RequestPasswordReset, h.RequestPasswordResetHandler)
	router.POST(server.V1_ResetPassword, h.ResetPasswordHandler)
	router.POST(server.V1_ChangePassword, h.ChangePasswordHandler)
	// MFA APIs
	router.POST(server.V1_MFAEnroll, h.MFAEnrollHandler)
	router.POST(server.V1_MFAVerifyEnrollment, h.MFAVerifyEnrollmentHandler)
	router.POST(server.V1_MFADisable, h.MFADisableHandler)
	router.POST(server.V1_MFAVerifyLogin, h.MFAVerifyLoginHandler)
	router.POST(server.V1_MFASendLoginCode, h.MFASendLoginCodeHandler)
	router.POST(server.V1_MFAEmailEnroll, h.MFAEmailEnrollHandler)
	router.POST(server.V1_MFAEmailVerify, h.MFAEmailVerifyEnrollmentHandler)
	router.POST(server.V1_MFAEmailDisable, h.MFAEmailDisableHandler)
	// SSO APIs
	router.POST(server.V1_SSOGoogle, h.SSOGoogleHandler)
	router.POST(server.V1_SSOApple, h.SSOAppleHandler)
	// Admin APIs — moderator+ unless noted otherwise
	router.GET(server.V1_AdminUsers, requireRole(postgres.UserRoleModerator, h.AdminListUsersHandler))
	router.GET(server.V1_AdminUserDetail, requireRole(postgres.UserRoleModerator, h.AdminGetUserHandler))
	router.POST(server.V1_AdminUserBan, requireRole(postgres.UserRoleModerator, h.AdminBanUserHandler))
	router.POST(server.V1_AdminUserUnban, requireRole(postgres.UserRoleModerator, h.AdminUnbanUserHandler))
	router.POST(server.V1_AdminUserDisable, requireRole(postgres.UserRoleModerator, h.AdminDisableUserHandler))
	router.POST(server.V1_AdminUserEnable, requireRole(postgres.UserRoleModerator, h.AdminEnableUserHandler))
	router.POST(server.V1_AdminUserForceLogout, requireRole(postgres.UserRoleModerator, h.AdminForceLogoutUserHandler))
	router.POST(server.V1_AdminUserResetPassword, requireRole(postgres.UserRoleModerator, h.AdminResetUserPasswordHandler))
	router.GET(server.V1_AdminAuditLogs, requireRole(postgres.UserRoleModerator, h.AdminListAuditLogsHandler))
	router.POST(server.V1_AdminUserRole, requireRole(postgres.UserRoleAdmin, h.AdminChangeUserRoleHandler)) // admin-only
	router.DELETE(server.V1_AdminUserDetail, requireRole(postgres.UserRoleAdmin, h.AdminDeleteUserHandler)) // admin-only
	// Passkey APIs
	router.POST(server.V1_PasskeyRegisterBegin, h.PasskeyRegisterBeginHandler)
	router.POST(server.V1_PasskeyRegisterFinish, h.PasskeyRegisterFinishHandler)
	router.POST(server.V1_PasskeyLoginBegin, h.PasskeyLoginBeginHandler)
	router.POST(server.V1_PasskeyLoginFinish, h.PasskeyLoginFinishHandler)
	router.GET(server.V1_PasskeyList, h.PasskeyListHandler)
	router.POST(server.V1_PasskeyRename, h.PasskeyRenameHandler)
	router.DELETE(server.V1_PasskeyDetail, h.PasskeyDeleteHandler)

	// Handle httprouter's default NotFound and MethodNotAllowed responses
	router.NotFound = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.JSONError(w, utils.Errors.RouteNotFound)
	})
	router.MethodNotAllowed = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.JSONError(w, utils.Errors.RouteNotFound)
	})

	return BuildHandlerStack(router, svcs)
}
