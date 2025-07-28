package utils

// ErrorCode defines a named constant for a specific error condition.
type ErrorCode string

// ErrorDetail holds both the code and a default message.
type ErrorDetail struct {
	Code    ErrorCode
	Message string
}

// Error registry: centralized place for all error definitions.
var Errors = struct {
	InvalidEmailFormat    ErrorDetail
	InvalidCodeFormat     ErrorDetail
	IncorrectCode         ErrorDetail
	CodeExpired           ErrorDetail
	CodeNotFound          ErrorDetail
	TooManyAttempts       ErrorDetail
	TokenGenerationFailed ErrorDetail
	InvalidPayload        ErrorDetail
	InternalServerError   ErrorDetail
	Unauthorized          ErrorDetail
	RouteNotFound         ErrorDetail
}{
	InvalidEmailFormat:    ErrorDetail{"invalid_email_format", "Invalid email format"},
	IncorrectCode:         ErrorDetail{"invalid_code", "Invalid verification code"},
	CodeExpired:           ErrorDetail{"code_expired", "Verification code has expired"},
	CodeNotFound:          ErrorDetail{"code_not_found", "Verification code not found or expired"},
	TooManyAttempts:       ErrorDetail{"too_many_attempts", "Too many failed attempts"},
	TokenGenerationFailed: ErrorDetail{"token_generation_failed", "Failed to generate token"},
	InvalidPayload:        ErrorDetail{"invalid_payload", "Invalid request payload"},
	InternalServerError:   ErrorDetail{"internal_server_error", "Something went wrong"},
	Unauthorized:          ErrorDetail{"unauthorized", "Unauthorized access"},
	RouteNotFound:         ErrorDetail{"route_not_found", "Requested route not found"},
}
