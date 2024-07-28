package data

import (
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrUserNotFound  = errors.New("user not found")
	ErrUsernameTaken = errors.New("username is already taken")
)

type Models struct {
	User UserModel
}

func NewModels(db *pgxpool.Pool) Models {
	return Models{
		User: UserModel{DB: db},
	}
}
