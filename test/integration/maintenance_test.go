package integration

import (
	"context"
	"testing"
	"time"

	"auth-api/internal/auth"
	"auth-api/internal/db/postgres"
	"auth-api/internal/services"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// The generated sqlc queries mostly use now() server-side rather than taking
// a timestamp param, since the app never needs to backdate a row — but
// these tests do, to put rows on the correct side of each cleanup
// function's cutoff without waiting real days/hours. Raw SQL against testDB
// is the simplest way to do that without adding test-only params to
// production queries.

func TestRunMaintenance_RemovesExpiredPasswordResets(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signup := signUpTestUser(t, ctx, email, "maintexpiredreset", "correct horse battery staple")
	userID := userUUID(t, signup.UserID)

	seedPasswordReset(t, ctx, userID, "maint-expired-token", time.Now().Add(-time.Hour))

	if err := services.RunMaintenance(ctx, testDB); err != nil {
		t.Fatalf("RunMaintenance: %v", err)
	}

	var count int
	if err := testDB.QueryRow(ctx, `SELECT count(*) FROM password_resets WHERE user_id = $1`, userID).Scan(&count); err != nil {
		t.Fatalf("counting password_resets: %v", err)
	}
	if count != 0 {
		t.Errorf("expected the expired password reset row to be deleted, %d remain", count)
	}
}

func TestRunMaintenance_KeepsOnlyFiveMostRecentPasswordResetsPerUser(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signup := signUpTestUser(t, ctx, email, "maintoldresets", "correct horse battery staple")
	userID := userUUID(t, signup.UserID)

	// 6 rows, each an hour apart and all still unexpired, so only
	// remove_old_password_resets (keep top 5 by created_at) applies —
	// remove_expired_password_resets should have nothing to do here.
	for i := 0; i < 6; i++ {
		createdAt := time.Now().Add(-time.Duration(i) * time.Hour)
		if _, err := testDB.Exec(ctx,
			`INSERT INTO password_resets (user_id, reset_token, created_at, expires_at, source)
			 VALUES ($1, $2, $3, $4, 'web')`,
			userID, auth.HashOpaqueToken(uuid.NewString()), createdAt, createdAt.Add(24*time.Hour),
		); err != nil {
			t.Fatalf("seeding password_resets row %d: %v", i, err)
		}
	}

	if err := services.RunMaintenance(ctx, testDB); err != nil {
		t.Fatalf("RunMaintenance: %v", err)
	}

	var count int
	if err := testDB.QueryRow(ctx, `SELECT count(*) FROM password_resets WHERE user_id = $1`, userID).Scan(&count); err != nil {
		t.Fatalf("counting password_resets: %v", err)
	}
	if count != 5 {
		t.Errorf("expected exactly 5 password_resets rows to remain, got %d", count)
	}
}

func TestRunMaintenance_RemovesOldLoginLogs(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signup := signUpTestUser(t, ctx, email, "maintoldlogins", "correct horse battery staple")
	userID := userUUID(t, signup.UserID)

	oldCreatedAt := time.Now().Add(-100 * 24 * time.Hour) // older than the 90-day retention window
	recentCreatedAt := time.Now().Add(-1 * time.Hour)
	if _, err := testDB.Exec(ctx,
		`INSERT INTO logins (user_id, result, created_at) VALUES ($1, 'success', $2)`,
		userID, oldCreatedAt,
	); err != nil {
		t.Fatalf("seeding old login: %v", err)
	}
	if _, err := testDB.Exec(ctx,
		`INSERT INTO logins (user_id, result, created_at) VALUES ($1, 'success', $2)`,
		userID, recentCreatedAt,
	); err != nil {
		t.Fatalf("seeding recent login: %v", err)
	}

	if err := services.RunMaintenance(ctx, testDB); err != nil {
		t.Fatalf("RunMaintenance: %v", err)
	}

	var count int
	if err := testDB.QueryRow(ctx, `SELECT count(*) FROM logins WHERE user_id = $1`, userID).Scan(&count); err != nil {
		t.Fatalf("counting logins: %v", err)
	}
	if count != 1 {
		t.Errorf("expected only the recent login row to remain, got %d rows", count)
	}
}

func TestRunMaintenance_RemovesUnverifiedMFAFactors(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signup := signUpTestUser(t, ctx, email, "maintunverifiedmfa", "correct horse battery staple")
	userID := userUUID(t, signup.UserID)

	oldCreatedAt := time.Now().Add(-3 * time.Hour) // older than the 2-hour grace window
	if _, err := testDB.Exec(ctx,
		`INSERT INTO mfa_factors (user_id, type, verified, created_at) VALUES ($1, 'totp', false, $2)`,
		userID, oldCreatedAt,
	); err != nil {
		t.Fatalf("seeding unverified mfa factor: %v", err)
	}

	if err := services.RunMaintenance(ctx, testDB); err != nil {
		t.Fatalf("RunMaintenance: %v", err)
	}

	var count int
	if err := testDB.QueryRow(ctx, `SELECT count(*) FROM mfa_factors WHERE user_id = $1`, userID).Scan(&count); err != nil {
		t.Fatalf("counting mfa_factors: %v", err)
	}
	if count != 0 {
		t.Errorf("expected the stale unverified mfa factor to be removed, %d remain", count)
	}
}

func TestRunMaintenance_RevokesExpiredAndOldSessions(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signup := signUpTestUser(t, ctx, email, "maintsessions", "correct horse battery staple")
	userID := userUUID(t, signup.UserID)

	expiredSessionID := pgtype.UUID{Bytes: uuid.New(), Valid: true}
	if _, err := testDB.Exec(ctx,
		`INSERT INTO sessions (id, user_id, created_at, expires_at, revoked) VALUES ($1, $2, now(), now() - interval '1 hour', false)`,
		expiredSessionID, userID,
	); err != nil {
		t.Fatalf("seeding expired session: %v", err)
	}

	oldSessionID := pgtype.UUID{Bytes: uuid.New(), Valid: true}
	if _, err := testDB.Exec(ctx,
		`INSERT INTO sessions (id, user_id, created_at, expires_at, revoked) VALUES ($1, $2, now() - interval '31 days', now() + interval '1 hour', false)`,
		oldSessionID, userID,
	); err != nil {
		t.Fatalf("seeding old (but not yet expired) session: %v", err)
	}

	liveSessionID := pgtype.UUID{Bytes: uuid.New(), Valid: true}
	if _, err := testDB.Exec(ctx,
		`INSERT INTO sessions (id, user_id, created_at, expires_at, revoked) VALUES ($1, $2, now(), now() + interval '1 hour', false)`,
		liveSessionID, userID,
	); err != nil {
		t.Fatalf("seeding live session: %v", err)
	}

	if err := services.RunMaintenance(ctx, testDB); err != nil {
		t.Fatalf("RunMaintenance: %v", err)
	}

	q := postgres.New(testDB)
	expired, err := q.GetRefreshSession(ctx, expiredSessionID)
	if err != nil {
		t.Fatalf("GetRefreshSession(expired): %v", err)
	}
	if !expired.Revoked.Bool {
		t.Error("expected the expired session to be revoked by revoke_expired_sessions")
	}

	old, err := q.GetRefreshSession(ctx, oldSessionID)
	if err != nil {
		t.Fatalf("GetRefreshSession(old): %v", err)
	}
	if !old.Revoked.Bool {
		t.Error("expected the >30-day-old session to be revoked by revoke_old_sessions regardless of its expires_at")
	}

	live, err := q.GetRefreshSession(ctx, liveSessionID)
	if err != nil {
		t.Fatalf("GetRefreshSession(live): %v", err)
	}
	if live.Revoked.Bool {
		t.Error("expected the live, recent, unexpired session to be left alone")
	}
}
