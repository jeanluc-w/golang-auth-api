package data

import (
	"edibubble/internal/validator"
)

// Verify the sessionToken exists and matches the GUID length (36 characters).
func ValidateSessionToken(v *validator.Validator, sessionToken string) {
	v.Check(sessionToken != "", "sessionToken", "must be provided")
	v.Check(len(sessionToken) == 36, "sessionToken", "must be a GUID")
}
