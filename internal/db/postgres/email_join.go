package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

type CreatedUser struct {
	ID       string
	Username string
}

// CreateEmailUser inserts a user and associated auth identity in one transaction.
func CreateEmailUser(ctx context.Context, db DBTX, email, username, passwordHash string) (*CreatedUser, error) {
	tx, err := db.(pgx.Tx)
	if !err {
		return nil, errors.New("invalid DBTX type for transaction")
	}

	qtx := New(tx)

	user, err := qtx.CreateUser(ctx, CreateUserParams{
		Email:    email,
		Username: username,
	})
	if err != nil {
		return nil, err
	}

	err = qtx.CreateAuthIdentity(ctx, CreateAuthIdentityParams{
		UserID:         user.ID,
		ProviderUserID: email,
		PasswordHash:   passwordHash,
	})
	if err != nil {
		return nil, err
	}

	return &CreatedUser{
		ID:       user.ID,
		Username: user.Username,
	}, nil
}
