package data

import (
	"context"
	"edibubble/internal/validator"
	"log/slog"
	"time"

	"cloud.google.com/go/firestore"
)

var AnonymousUser = &User{}

type User struct {
	ID            string `json:"id" firestore:"-"`
	Username      string `json:"username" firestore:"username"`
	Name          string `json:"name" firestore:"name"`
	Email         string `json:"-" firestore:"email"`
	EmailVerified bool   `json:"-" firestore:"emailVerified"`
	Image         string `json:"profile_picture" firestore:"image"`
}

type UserModel struct {
	DB *firestore.Client
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
	logger.Info("SetUsername - Starting search", "user id", user.ID, "username", user.Username)
	// Search if we have a record of the username
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	query := u.DB.Collection("users").Where("username", "==", user.Username).Limit(1)
	results, err := query.Documents(ctx).GetAll()
	if err != nil {
		return err
	}
	if results[0].Exists() {
		logger.Info("SetUsername - username already exists on another account.")
		return ErrUsernameTaken
	}
	data := map[string]interface{}{
		"username": user.Username,
	}
	_, err = u.DB.Collection("users").Doc(user.ID).Set(ctx, data, firestore.MergeAll)
	return err
}

// Searches for the user ID by the sessionToken. Used to authenticate a user exists in the DB.
// We don't care to pull all the user information at this stage as it could be used a lot for linking
// to other records (e.g. lists or following link tables)
func (u UserModel) GetUserID(sessionToken string, logger *slog.Logger) (*User, error) {
	var user User
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	query := u.DB.Collection("sessions").Where("sessionToken", "==", sessionToken).Where("expires", ">", time.Now()).Limit(1)
	results, err := query.Documents(ctx).GetAll()
	if err != nil {
		return nil, err
	}
	if len(results) > 0 {
		if err := results[0].DataTo(&user); err != nil {
			return nil, err
		}
		return &user, nil
	}
	return nil, ErrUserNotFound
}
