package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// WithActor runs fn inside a transaction with the Postgres session variable
// app.actor_id set (transaction-locally) to actorID first. Every audit-log
// trigger in 002_log_triggers.up.sql reads that variable via
// current_setting('app.actor_id', true) to attribute a change to whoever
// made it; without this, admin-performed changes would still be logged,
// just with a NULL actor — indistinguishable from a user acting on their
// own account. It must be a real transaction (not two separate statements)
// because set_config's is_local=true resets the value at the end of the
// current transaction, and a pooled connection is reused across unrelated
// requests.
func WithActor(ctx context.Context, db *pgxpool.Pool, actorID string, fn func(*Queries) error) error {
	return WithTx(ctx, db, func(qtx *Queries) error {
		if err := qtx.SetActorID(ctx, actorID); err != nil {
			return err
		}
		return fn(qtx)
	})
}
