package data

import (
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNoRows        = pgx.ErrNoRows
	ErrUserNotFound  = errors.New("user could not be found")
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
