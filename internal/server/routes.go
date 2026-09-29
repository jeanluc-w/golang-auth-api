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
	V1_SSOGoogle              string = "/auth/v1/sso/google"
	V1_SSOApple               string = "/auth/v1/sso/apple"
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
	V1_SSOGoogle,
	V1_SSOApple,
}

// Routes where only Temporary JWTs are allowed (essentially sign-ups)
var TemporaryJWTRoutes = []string{
	V1_CompleteEmailJoin,
}
