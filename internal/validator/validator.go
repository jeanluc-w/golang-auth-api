package validator

import (
	"regexp"
	"slices"
)

// Declare regular expression for sanity checking:
// - Email addresses (taken from https://html.spec.whatwg.org/#valid-e-mail-address)
// - Username (only 2-30 characters length and only letters, numbers, and . or _ allowed)
var (
	EmailRX    = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	UsernameRX = regexp.MustCompile("^[a-zA-Z0-9_.]{2,30}$")
)

// Validator type which contains a map of validation errors
type Validator struct {
	Errors map[string]string
}

// Initializer for Validator instance with an empty errors map
func New() *Validator {
	return &Validator{Errors: make(map[string]string)}
}

func (v *Validator) Valid() bool {
	return len(v.Errors) == 0
}

// Add errors to the map when the error key doesn't already exist in the map
func (v *Validator) AddError(key, message string) {
	if _, exists := v.Errors[key]; !exists {
		v.Errors[key] = message
	}
}

// Adds error message to the map if the validation check isn't 'ok'
func (v *Validator) Check(ok bool, key, message string) {
	if !ok {
		v.AddError(key, message)
	}
}

// Generic function which returns true if the provided value is allowed in a list of permitted values
func PermittedValue[T comparable](value T, permittedValues ...T) bool {
	return slices.Contains(permittedValues, value)
}

// Generic function which returns true if a string matches the regexp pattern
func Matches(value string, rx *regexp.Regexp) bool {
	return rx.MatchString(value)
}

// Generic function which returns true if all values in a slice are unique
func Unique[T comparable](values []T) bool {
	uniqueValues := make(map[T]bool)

	for _, value := range values {
		uniqueValues[value] = true
	}

	return len(values) == len(uniqueValues)
}
