package utils

import "regexp"

// Email regex verifies that the email matches:
// - Isn't empty
// - Starts with alphanumeric characters
// - Contains only alphanumeric characters, dots, underscores, and hyphens
// - Ends with a valid domain format
// - Domain must have at least one dot and a valid TLD
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// Username regex verifies that the username matches:
// - Isn't empty
// - Starts with an alphanumeric character
// - Contains only alphanumeric characters, dots, and underscores in between (if any)
// - Ends with an alphanumeric character
// - Length between 2 and 30 characters (inclusive)
var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9._]{0,28}[a-zA-Z0-9])?$`)

// Verification code regex verifies that the code matches:
// - Is exactly 6 digits long
var verificationCodeRegex = regexp.MustCompile(`^\d{6}$`)

func IsValidEmail(email string) bool {
	return emailRegex.MatchString(email)
}
func IsValidUsername(username string) bool {
	return usernameRegex.MatchString(username)
}
func IsValidPassword(password string) bool {
	return len(password) >= 12
}
func IsValidVerificationCode(code string) bool {
	return verificationCodeRegex.MatchString(code)
}

// IsOriginAllowed checks if the given origin is in the provided whitelist
func IsOriginAllowed(origin string, whitelist []string) bool {
	for _, allowed := range whitelist {
		if origin == allowed {
			return true
		}
	}
	return false
}
