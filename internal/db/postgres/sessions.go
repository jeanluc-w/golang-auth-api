// internal/db/postgres/sessions.go
package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type RefreshSessionInput struct {
	SessionID        string
	UserID           pgtype.UUID
	ExpiresAt        time.Time
	RefreshTokenHash string
	IP               string
	UserAgent        string
}

func CreateRefreshSession(ctx context.Context, q *Queries, in RefreshSessionInput) (CreateRefreshSessionRow, error) {
	sid, _ := uuid.Parse(in.SessionID)

	return q.CreateRefreshSession(ctx, CreateRefreshSessionParams{
		ID:               pgtype.UUID{Bytes: sid, Valid: true},
		UserID:           in.UserID,
		ExpiresAt:        pgtype.Timestamptz{Time: in.ExpiresAt, Valid: true},
		RefreshTokenHash: pgtype.Text{String: in.RefreshTokenHash, Valid: true},
		Ip:               pgtype.Text{String: in.IP, Valid: in.IP != ""},
		UserAgent:        pgtype.Text{String: in.UserAgent, Valid: in.UserAgent != ""},
		// TODO Add metadata
	})
}
