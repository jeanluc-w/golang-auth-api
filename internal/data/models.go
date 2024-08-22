package data

import (
	"errors"

	"cloud.google.com/go/firestore"
)

var (
	ErrUserNotFound  = errors.New("user could not be found")
	ErrUsernameTaken = errors.New("username is already taken")
)

type Models struct {
	User UserModel
}

func NewModels(client *firestore.Client) Models {
	return Models{
		User: UserModel{DB: client},
	}
}
