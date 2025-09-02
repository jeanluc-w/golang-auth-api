package auth

import (
	"context"
	"edibubble-api/internal/db/postgres"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Checks if an email is already registered to an email auth identity in the DB.
func IsEmailTaken(ctx context.Context, email string, db *pgxpool.Pool) (bool, error) {
	var taken bool
	err := postgres.WithTx(ctx, db, func(q *postgres.Queries) error {
		result, err := q.IsEmailRegistered(ctx, email)
		if err != nil {
			return err
		}
		taken = result
		return nil
	})
	return taken, err
}
