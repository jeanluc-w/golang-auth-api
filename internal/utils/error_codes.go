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
	CodeExpired           ErrorDetail
	IncorrectCode         ErrorDetail
	InternalServerError   ErrorDetail
	InvalidEmailFormat    ErrorDetail
	InvalidPayload        ErrorDetail
	InvalidUsernameFormat ErrorDetail
	RouteNotFound         ErrorDetail
	TooManyAttempts       ErrorDetail
	Unauthorized          ErrorDetail
	UsernameTaken         ErrorDetail
}{
	CodeExpired:           ErrorDetail{"code_expired", "Verification code has expired"},
	IncorrectCode:         ErrorDetail{"invalid_code", "Invalid verification code"},
	InternalServerError:   ErrorDetail{"internal_server_error", "Something went wrong"},
	InvalidEmailFormat:    ErrorDetail{"invalid_email_format", "Invalid email submitted"},
	InvalidPayload:        ErrorDetail{"invalid_payload", "Invalid request payload"},
	InvalidUsernameFormat: ErrorDetail{"invalid_username_format", "Invalid username submitted"},
	RouteNotFound:         ErrorDetail{"route_not_found", "Requested route not found"},
	TooManyAttempts:       ErrorDetail{"too_many_attempts", "Too many failed attempts"},
	Unauthorized:          ErrorDetail{"unauthorized", "Unauthorized access"},
	UsernameTaken:         ErrorDetail{"username_taken", "Username already in use"},
}
