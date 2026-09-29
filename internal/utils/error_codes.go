package utils

import "net/http"

// ErrorDetail holds both the code, default message, and the HTTP status code
type ErrorDetail struct {
	Code    string
	Message string
	Status  int
}

// Error registry: centralized place for all error definitions.
var Errors = struct {
	AccountLocked             ErrorDetail
	AccountNotUsable          ErrorDetail
	AdminProtected            ErrorDetail
	CannotTargetSelf          ErrorDetail
	CodeExpired               ErrorDetail
	EmailIsTaken              ErrorDetail
	Forbidden                 ErrorDetail
	IncorrectCode             ErrorDetail
	InternalServerError       ErrorDetail
	InvalidCredentials        ErrorDetail
	InvalidEmailFormat        ErrorDetail
	InvalidMFACode            ErrorDetail
	InvalidOrExpiredToken     ErrorDetail
	InvalidPasswordFormat     ErrorDetail
	InvalidPayload            ErrorDetail
	InvalidPayloadMedia       ErrorDetail
	InvalidPayloadSize        ErrorDetail
	InvalidRole               ErrorDetail
	InvalidUsernameFormat     ErrorDetail
	MFAAlreadyEnabled         ErrorDetail
	MFANotEnabled             ErrorDetail
	NewPasswordMatchesCurrent ErrorDetail
	RouteNotFound             ErrorDetail
	SessionExpired            ErrorDetail
	SSOAccountConflict        ErrorDetail
	SSOEmailNotVerified       ErrorDetail
	SSONotConfigured          ErrorDetail
	SSOTokenInvalid           ErrorDetail
	TooManyAttempts           ErrorDetail
	TooSoonToRequest          ErrorDetail
	Unauthorized              ErrorDetail
	UserNotFound              ErrorDetail
	UsernameTaken             ErrorDetail
	TokenGenerationFailed     ErrorDetail
}{
	AccountLocked:             ErrorDetail{"account_locked", "Account temporarily locked due to too many failed login attempts", http.StatusLocked},                   // 423
	AccountNotUsable:          ErrorDetail{"account_not_usable", "This account cannot currently sign in", http.StatusForbidden},                                       // 403
	AdminProtected:            ErrorDetail{"admin_protected", "This action cannot be performed on an admin account", http.StatusForbidden},                            // 403
	CannotTargetSelf:          ErrorDetail{"cannot_target_self", "This action cannot be performed on your own account", http.StatusBadRequest},                        // 400
	CodeExpired:               ErrorDetail{"code_expired", "Verification code has expired", http.StatusUnauthorized},                                                  // 401
	EmailIsTaken:              ErrorDetail{"email_is_taken", "Email is already taken", http.StatusConflict},                                                           // 409
	Forbidden:                 ErrorDetail{"forbidden", "You do not have permission to perform this action", http.StatusForbidden},                                    // 403
	IncorrectCode:             ErrorDetail{"invalid_code", "Invalid verification code", http.StatusUnauthorized},                                                      // 401
	InternalServerError:       ErrorDetail{"internal_server_error", "Something went wrong", http.StatusInternalServerError},                                           // 500
	InvalidCredentials:        ErrorDetail{"invalid_credentials", "Invalid email or password", http.StatusUnauthorized},                                               // 401
	InvalidEmailFormat:        ErrorDetail{"invalid_email_format", "Invalid email submitted", http.StatusBadRequest},                                                  // 400
	InvalidMFACode:            ErrorDetail{"invalid_mfa_code", "Invalid or expired MFA code", http.StatusUnauthorized},                                                // 401
	InvalidOrExpiredToken:     ErrorDetail{"invalid_or_expired_token", "This link is invalid or has expired", http.StatusUnauthorized},                                // 401
	InvalidPasswordFormat:     ErrorDetail{"invalid_password_format", "Invalid password length", http.StatusBadRequest},                                               // 400
	InvalidPayload:            ErrorDetail{"invalid_payload", "Invalid request payload", http.StatusBadRequest},                                                       // 400
	InvalidPayloadSize:        ErrorDetail{"invalid_payload", "Invalid request payload", http.StatusRequestEntityTooLarge},                                            // 413
	InvalidPayloadMedia:       ErrorDetail{"invalid_payload", "Invalid request payload", http.StatusUnsupportedMediaType},                                             // 415
	InvalidRole:               ErrorDetail{"invalid_role", "Invalid role submitted", http.StatusBadRequest},                                                           // 400
	InvalidUsernameFormat:     ErrorDetail{"invalid_username_format", "Invalid username submitted", http.StatusBadRequest},                                            // 400
	MFAAlreadyEnabled:         ErrorDetail{"mfa_already_enabled", "MFA is already enabled for this account", http.StatusConflict},                                     // 409
	MFANotEnabled:             ErrorDetail{"mfa_not_enabled", "MFA is not enabled for this account", http.StatusBadRequest},                                           // 400
	NewPasswordMatchesCurrent: ErrorDetail{"new_password_matches_current", "New password must be different from your current password", http.StatusBadRequest},        // 400
	RouteNotFound:             ErrorDetail{"route_not_found", "Requested route not found", http.StatusNotFound},                                                       // 404
	SessionExpired:            ErrorDetail{"session_expired", "Refresh token is invalid or expired", http.StatusUnauthorized},                                         // 401
	SSOAccountConflict:        ErrorDetail{"sso_account_conflict", "An account already exists with this email using a different sign-in method", http.StatusConflict}, // 409
	SSOEmailNotVerified:       ErrorDetail{"sso_email_not_verified", "Your account email is not verified with the identity provider", http.StatusForbidden},           // 403
	SSONotConfigured:          ErrorDetail{"sso_not_configured", "This sign-in method is not available", http.StatusServiceUnavailable},                               // 503
	SSOTokenInvalid:           ErrorDetail{"sso_token_invalid", "Could not verify the provided identity token", http.StatusUnauthorized},                              // 401
	TooManyAttempts:           ErrorDetail{"too_many_attempts", "Too many failed attempts", http.StatusTooManyRequests},                                               // 429
	TooSoonToRequest:          ErrorDetail{"too_soon_to_request", "Please wait before requesting another code", http.StatusTooManyRequests},                           // 429
	Unauthorized:              ErrorDetail{"unauthorized", "Unauthorized access", http.StatusUnauthorized},                                                            // 401
	UserNotFound:              ErrorDetail{"user_not_found", "User not found", http.StatusNotFound},                                                                   // 404
	UsernameTaken:             ErrorDetail{"username_taken", "Username already in use", http.StatusConflict},                                                          // 409
	TokenGenerationFailed:     ErrorDetail{"session_generation_failed", "Failed to generate session, please log-in", http.StatusInternalServerError},                  // 500
}
