package server

const (
	V1_HealthCheck            string = "/v1/healthcheck"
	V1_Login                  string = "/auth/v1/login"
	V1_Logout                 string = "/auth/v1/logout"
	V1_StartEmailVerification string = "/auth/v1/start-email-verification"
	V1_VerifyEmail            string = "/auth/v1/verify-email"
	V1_CompleteEmailJoin      string = "/auth/v1/complete-email-join"
	V1_RefreshToken           string = "/auth/v1/refresh-token"
	// Not yet implemented — the DB schema (password_resets, mfa_factors
	// tables) already supports them; see the README's "Not implemented" section.
	// Forgot password
	// Change Password
	// SSO
)

// Routes where JWT validation isn't needed
var OpenRoutes = []string{
	V1_HealthCheck,
	V1_StartEmailVerification,
	V1_VerifyEmail,
	V1_Login,
}

// Routes where only Temporary JWTs are allowed (essentially sign-ups)
var TemporaryJWTRoutes = []string{
	V1_CompleteEmailJoin,
}
