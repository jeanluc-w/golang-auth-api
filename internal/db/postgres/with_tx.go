package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WithTx wraps a pgx transaction and gives you a sqlc-ready Queries instance.
func WithTx(ctx context.Context, db *pgxpool.Pool, fn func(*Queries) error) error {
	tx, err := db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("failed to begin tx: %w", err)
	}
	defer tx.Rollback(ctx) // safe to call even after commit

	qtx := New(tx)

	if err := fn(qtx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("tx commit failed: %w", err)
	}

	return nil
}
