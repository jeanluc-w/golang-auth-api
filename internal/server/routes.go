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
	// Not yet implemented — the DB schema (mfa_factors table) already
	// supports it; see the README's "Not implemented" section.
	// Change Password (while authenticated, as opposed to a forgotten-password reset)
	// SSO
)

// Routes where JWT validation isn't needed
var OpenRoutes = []string{
	V1_HealthCheck,
	V1_StartEmailVerification,
	V1_VerifyEmail,
	V1_Login,
	V1_RequestPasswordReset,
	V1_ResetPassword,
}

// Routes where only Temporary JWTs are allowed (essentially sign-ups)
var TemporaryJWTRoutes = []string{
	V1_CompleteEmailJoin,
}
