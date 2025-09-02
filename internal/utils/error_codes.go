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
	CodeExpired           ErrorDetail
	EmailIsTaken          ErrorDetail
	IncorrectCode         ErrorDetail
	InternalServerError   ErrorDetail
	InvalidEmailFormat    ErrorDetail
	InvalidPasswordFormat ErrorDetail
	InvalidPayload        ErrorDetail
	InvalidPayloadMedia   ErrorDetail
	InvalidPayloadSize    ErrorDetail
	InvalidUsernameFormat ErrorDetail
	RouteNotFound         ErrorDetail
	TooManyAttempts       ErrorDetail
	Unauthorized          ErrorDetail
	UsernameTaken         ErrorDetail
	TokenGenerationFailed ErrorDetail
}{
	CodeExpired:           ErrorDetail{"code_expired", "Verification code has expired", http.StatusUnauthorized},                                 // 401
	EmailIsTaken:          ErrorDetail{"email_is_taken", "Email is already taken", http.StatusConflict},                                          // 409
	IncorrectCode:         ErrorDetail{"invalid_code", "Invalid verification code", http.StatusUnauthorized},                                     // 401
	InternalServerError:   ErrorDetail{"internal_server_error", "Something went wrong", http.StatusInternalServerError},                          // 500
	InvalidEmailFormat:    ErrorDetail{"invalid_email_format", "Invalid email submitted", http.StatusBadRequest},                                 // 400
	InvalidPasswordFormat: ErrorDetail{"invalid_password_format", "Invalid password length", http.StatusBadRequest},                              // 400
	InvalidPayload:        ErrorDetail{"invalid_payload", "Invalid request payload", http.StatusBadRequest},                                      // 400
	InvalidPayloadSize:    ErrorDetail{"invalid_payload", "Invalid request payload", http.StatusRequestEntityTooLarge},                           // 413
	InvalidPayloadMedia:   ErrorDetail{"invalid_payload", "Invalid request payload", http.StatusUnsupportedMediaType},                            // 415
	InvalidUsernameFormat: ErrorDetail{"invalid_username_format", "Invalid username submitted", http.StatusBadRequest},                           // 400
	RouteNotFound:         ErrorDetail{"route_not_found", "Requested route not found", http.StatusNotFound},                                      // 404
	TooManyAttempts:       ErrorDetail{"too_many_attempts", "Too many failed attempts", http.StatusTooManyRequests},                              // 429
	Unauthorized:          ErrorDetail{"unauthorized", "Unauthorized access", http.StatusUnauthorized},                                           // 401
	UsernameTaken:         ErrorDetail{"username_taken", "Username already in use", http.StatusConflict},                                         // 409
	TokenGenerationFailed: ErrorDetail{"session_generation_failed", "Failed to generate session, please log-in", http.StatusInternalServerError}, // 500
}
