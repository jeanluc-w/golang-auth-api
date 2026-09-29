package services

import (
	"context"
	"fmt"

	"auth-api/internal/db/postgres"
	"auth-api/internal/utils"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// maintenanceJob pairs a human-readable name with the query that runs it,
// so RunMaintenance can log and report failures per-job without repeating
// the same boilerplate six times.
type maintenanceJob struct {
	name string
	run  func(*postgres.Queries, context.Context) error
}

// jobs mirrors the cleanup functions defined in
// db/migrations/004_revoke_triggers.up.sql. Nothing in the request-serving
// path calls these — see cmd/cron, which runs RunMaintenance on a schedule
// via an external cron/CronJob.
var jobs = []maintenanceJob{
	{"remove_expired_password_resets", (*postgres.Queries).RemoveExpiredPasswordResets},
	{"remove_old_password_resets", (*postgres.Queries).RemoveOldPasswordResets},
	{"remove_old_login_logs", (*postgres.Queries).RemoveOldLoginLogs},
	{"remove_unverified_mfa_factors", (*postgres.Queries).RemoveUnverifiedMFAFactors},
	{"revoke_expired_sessions", (*postgres.Queries).RevokeExpiredSessions},
	{"revoke_old_sessions", (*postgres.Queries).RevokeOldSessions},
}

// RunMaintenance runs every scheduled cleanup job against db, in sequence.
// A failure in one job is logged and collected but doesn't stop the rest
// from running — an outage in, say, session cleanup shouldn't also block
// login-log retention. It returns one combined error listing every job that
// failed (nil if all succeeded), which callers can use as an exit-code
// signal for external monitoring.
func RunMaintenance(ctx context.Context, db *pgxpool.Pool) error {
	q := postgres.New(db)

	var failed []string
	for _, job := range jobs {
		if err := job.run(q, ctx); err != nil {
			utils.LogError(ctx, "Maintenance job failed", zap.String("job", job.name), zap.Error(err))
			failed = append(failed, job.name)
			continue
		}
		utils.LogInfo(ctx, "Maintenance job completed", zap.String("job", job.name))
	}

	if len(failed) > 0 {
		return fmt.Errorf("%d maintenance job(s) failed: %v", len(failed), failed)
	}
	return nil
}
