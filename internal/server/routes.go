package server

const (
	V1_HealthCheck            string = "/v1/healthcheck"
	V1_Login                  string = "/auth/v1/login"
	V1_Logout                 string = "/auth/v1/logout"
	V1_StartEmailVerification string = "/auth/v1/start-email-verification"
	V1_VerifyEmail            string = "/auth/v1/verify-email"
	V1_CompleteEmailJoin      string = "/auth/v1/complete-email-join"
	V1_RefreshToken           string = "/auth/v1/refresh-token"
	V1_RequestPasswordReset   string = "/auth/v1/request-password-reset"
	V1_ResetPassword          string = "/auth/v1/reset-password"
	V1_ChangePassword         string = "/auth/v1/change-password"
	V1_MFAEnroll              string = "/auth/v1/mfa/enroll"
	V1_MFAVerifyEnrollment    string = "/auth/v1/mfa/verify"
	V1_MFADisable             string = "/auth/v1/mfa/disable"
	V1_MFAVerifyLogin         string = "/auth/v1/mfa/verify-login"
	V1_MFASendLoginCode       string = "/auth/v1/mfa/send-login-code"
	V1_MFAEmailEnroll         string = "/auth/v1/mfa/email/enroll"
	V1_MFAEmailVerify         string = "/auth/v1/mfa/email/verify"
	V1_MFAEmailDisable        string = "/auth/v1/mfa/email/disable"
	V1_SSOGoogle              string = "/auth/v1/sso/google"
	V1_SSOApple               string = "/auth/v1/sso/apple"
	// Admin APIs (moderator+/admin-only — see handlers.requireRole)
	V1_AdminUsers             string = "/auth/v1/admin/users"
	V1_AdminUserDetail        string = "/auth/v1/admin/users/:id"
	V1_AdminUserBan           string = "/auth/v1/admin/users/:id/ban"
	V1_AdminUserUnban         string = "/auth/v1/admin/users/:id/unban"
	V1_AdminUserDisable       string = "/auth/v1/admin/users/:id/disable"
	V1_AdminUserEnable        string = "/auth/v1/admin/users/:id/enable"
	V1_AdminUserForceLogout   string = "/auth/v1/admin/users/:id/force-logout"
	V1_AdminUserResetPassword string = "/auth/v1/admin/users/:id/reset-password"
	V1_AdminUserRole          string = "/auth/v1/admin/users/:id/role"
	V1_AdminAuditLogs         string = "/auth/v1/admin/audit-logs"
	// Passkey (WebAuthn) APIs. Management routes live under
	// .../passkey/credentials/... rather than directly under .../passkey/:id
	// — httprouter (github.com/julienschmidt/httprouter) builds one radix
	// tree per HTTP method and panics at registration time if a literal
	// segment (e.g. "register") and a wildcard (":id") would both appear as
	// children of the same node for the same method, which is exactly what
	// .../passkey/register/begin (POST) alongside .../passkey/:id/rename
	// (POST) would do. Nesting the wildcard under its own literal prefix
	// avoids that collision entirely.
	V1_PasskeyRegisterBegin  string = "/auth/v1/passkey/register/begin"
	V1_PasskeyRegisterFinish string = "/auth/v1/passkey/register/finish"
	V1_PasskeyLoginBegin     string = "/auth/v1/passkey/login/begin"
	V1_PasskeyLoginFinish    string = "/auth/v1/passkey/login/finish"
	V1_PasskeyList           string = "/auth/v1/passkey/credentials"
	V1_PasskeyRename         string = "/auth/v1/passkey/credentials/:id/rename"
	V1_PasskeyDetail         string = "/auth/v1/passkey/credentials/:id"
)

// Routes where JWT validation isn't needed
var OpenRoutes = []string{
	V1_HealthCheck,
	V1_StartEmailVerification,
	V1_VerifyEmail,
	V1_Login,
	V1_RequestPasswordReset,
	V1_ResetPassword,
	// MFAVerifyLogin is unauthenticated-by-access-token on purpose: the
	// caller doesn't have a full session yet (that's the whole point — MFA
	// gates issuing one). It authenticates itself via the short-lived
	// mfa_pending challenge token carried in its own request body instead
	// of the Authorization header; see services.VerifyMFALogin.
	V1_MFAVerifyLogin,
	// Same reasoning as V1_MFAVerifyLogin: authenticates via the challenge
	// token in the body, not a full session.
	V1_MFASendLoginCode,
	V1_SSOGoogle,
	V1_SSOApple,
	// Passkey login has no session yet either — same reasoning as
	// V1_MFAVerifyLogin/V1_MFASendLoginCode. Registration, by contrast, is
	// authenticated (it's adding a passkey to an existing session) and is
	// NOT an open route.
	V1_PasskeyLoginBegin,
	V1_PasskeyLoginFinish,
}

// Routes where only Temporary JWTs are allowed (essentially sign-ups)
var TemporaryJWTRoutes = []string{
	V1_CompleteEmailJoin,
}
