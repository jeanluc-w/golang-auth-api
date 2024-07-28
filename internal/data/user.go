package data

import (
	"edibubble/internal/validator"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Getting a user's account
type User struct {
	ID            int64  `json:"id"`
	Username      string `json:"username"`
	Name          string `json:"name"`
	Email         string `json:"-"`
	EmailVerified bool   `json:"-"`
	Image         string `json:"profile_picture"`
}

type UserModel struct {
	DB *pgxpool.Pool
}

// Validate a username is proper length and has valid characters.
func ValidateUsername(v *validator.Validator, username string) {
	// Although the Regex will cover all of the checks, we want separate checks to return descriptive errors
	v.Check(len(username) >= 2, "username-too_short", "must be at least 2 characters long")
	v.Check(len(username) <= 30, "username-too_long", "must be less than 30 characters long")
	v.Check(validator.Matches(username, validator.UsernameRX), "username-illegal_characters", "must only contain letters, numbers, periods or underscores")
}

// TODO: Improve validation once user struct is determined.

// Validate a User object has a valid username, email, and name.
func ValidateUser(v *validator.Validator, user *User) {
	ValidateUsername(v, user.Username)
	v.Check(len(user.Name) <= 70, "name-too_long", "must be less than or equal to 70 characters long")
	v.Check(validator.Matches(user.Email, validator.EmailRX), "email-illegal_characters", "must be a valid email address")
}

func (u UserModel) SearchUsername(username string) error {
	return nil
}
