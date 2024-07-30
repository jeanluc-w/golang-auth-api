package data

import (
	"context"
	"edibubble/internal/validator"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var AnonymousUser = &User{}

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

func (u *User) IsAnonymous() bool {
	return u == AnonymousUser
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

func (u UserModel) SetUsername(user *User, logger *slog.Logger) error {
	// Build the query to check if the username exists
	query := `
		SELECT id 
		FROM users 
		WHERE username = $1
		LIMIT 1;
	`
	args := []any{
		user.Username,
	}
	logger.Info("SetUsername - Search Arguments", "Args", args)
	// Search if we have a record of the username
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var id int
	err := u.DB.QueryRow(ctx, query, args...).Scan(&id)
	logger.Info("SetUsername - Search Results", "userId", id, "Err", err)

	if err != nil {
		switch {
		// If we didn't get a row searching for the username, set the username
		case errors.Is(err, ErrNoRows):
			query = `
				UPDATE users
				SET username = $1
				WHERE id = $2
				RETURNING username;
			`
			args = []any{
				user.Username,
				user.ID,
			}
			logger.Info("SetUsername - Update Arguments", "Args", args)
			ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			return u.DB.QueryRow(ctx, query, args...).Scan(&user.Username)
		default:
			return err
		}
	}

	return ErrUsernameTaken
}

// Searches for the user ID by the sessionToken. Used to authenticate a user exists in the DB.
// We don't care to pull all the user information at this stage as it could be used a lot for linking
// to other records (e.g. lists or following link tables)
func (u UserModel) GetUserID(sessionToken string, logger *slog.Logger) (*User, error) {
	query := `
		SELECT "userId"
		FROM sessions
		WHERE "sessionToken" = $1
		AND expires > $2;
	`
	args := []any{
		sessionToken,
		time.Now(),
	}

	var user User

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := u.DB.QueryRow(ctx, query, args...).Scan(&user.ID)
	logger.Info("GetUserID - userId lookup", "Err", err)
	if err != nil {
		switch {
		case errors.Is(err, ErrNoRows):
			return nil, ErrNoRows
		default:
			return nil, err
		}
	}
	return &user, nil
}
