package postgres

import (
	"context"
	"edibubble-api/internal/utils"
	"errors"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

type CreatedUser struct {
	ID              pgtype.UUID
	Username        string
	UsernameDisplay string
	Role            UserRole
}

// Starts a transaction, creates the user + email auth, and returns the created user.
func CreateEmailUser(ctx context.Context, db *pgxpool.Pool, email, username, passwordHash string) (*CreatedUser, error) {
	var out *CreatedUser

	err := WithTx(ctx, db, func(q *Queries) error {
		u, err := CreateEmailUserInTx(ctx, q, email, username, passwordHash)
		if err != nil {
			return err
		}
		out = u
		return nil
	})
	return out, err
}

// Inserts a user and associated auth identity in the DB.
func CreateEmailUserInTx(ctx context.Context, q *Queries, email, username, passwordHash string) (*CreatedUser, error) {
	// Check that the username wasn't taken again in case of race condition
	taken, err := q.UsernameExists(ctx, username)
	if err != nil {
		utils.LogError(ctx, "UsernameExists 2nd check failed", zap.Error(err))
		return nil, err
	}
	if taken {
		utils.LogInfo(ctx, "Username already taken")
		return nil, errors.New("username taken")
	}

	// Create the user
	user, err := q.CreateUser(ctx, CreateUserParams{
		Email:           email,
		UsernameDisplay: username,
	})
	if err != nil {
		utils.LogError(ctx, "Failed to create user in DB", zap.Error(err))
		return nil, err
	}
	if !user.ID.Valid {
		return nil, errors.New("User ID somehow failed")
	}

	// Create the user's email auth object
	if err := q.CreateEmailAuth(ctx, CreateEmailAuthParams{
		UserID:       user.ID,
		Email:        email,
		PasswordHash: pgtype.Text{String: passwordHash, Valid: true},
	}); err != nil {
		utils.LogError(ctx, "Failed to create the email auth object in DB", zap.Error(err))
		return nil, err
	}

	return &CreatedUser{
		ID:              user.ID,
		Username:        user.Username,
		UsernameDisplay: user.UsernameDisplay,
		Role:            user.Role,
	}, nil
}
