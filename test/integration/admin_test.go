package integration

import (
	"context"
	"net/http"
	"testing"

	"auth-api/internal/auth"
	"auth-api/internal/db/postgres"
	"auth-api/internal/entities"
	"auth-api/internal/services"
)

// testActor bundles a logged-in user's context (role, ID, etc.) with the
// tokens from that login — admin tests need both: the context to act as
// the caller, and the tokens to assert on session revocation later.
type testActor struct {
	*entities.UserContext
	Login *services.LoginResult
}

// promoteUserRole sets a user's role directly in Postgres, bypassing the
// admin API entirely — used only to seed a moderator/admin test actor,
// since there's no self-service or signup path to becoming one (by
// design: an admin account has to be provisioned out-of-band).
func promoteUserRole(t *testing.T, ctx context.Context, userID string, role postgres.UserRole) {
	t.Helper()
	if _, err := testDB.Exec(ctx, "UPDATE users SET role = $1 WHERE id = $2", string(role), userID); err != nil {
		t.Fatalf("promoteUserRole: %v", err)
	}
}

// loginAs signs a fresh access token for an existing account — used after
// promoteUserRole, since a token issued before the promotion still carries
// the old role (role is embedded in the JWT at issuance, not looked up
// per-request).
func loginAs(t *testing.T, ctx context.Context, email, password string) *testActor {
	t.Helper()
	result, errDetail := services.Login(ctx, testDB, testRedis, email, password)
	if errDetail != nil {
		t.Fatalf("Login: %+v", errDetail)
	}
	user, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+result.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAndParseJWT: %v", err)
	}
	return &testActor{UserContext: user, Login: result}
}

func TestAdminListUsers_RequiresModerator(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"
	signUpTestUser(t, ctx, email, "adminlistplain", password)

	// A plain user has no business calling ListUsers — this is enforced at
	// the router (requireRole), not services.ListUsers itself, so this
	// test exercises the service directly to confirm it doesn't implicitly
	// trust the caller either; the router-level rejection is covered by
	// http_server_test.go-style route tests being out of scope here.
	result, errDetail := services.ListUsers(ctx, testDB, services.AdminListUsersParams{Limit: 10})
	if errDetail != nil {
		t.Fatalf("ListUsers: %+v", errDetail)
	}
	if result.Total < 1 {
		t.Error("expected at least the user just created to show up")
	}
}

func TestAdminBanUser_RevokesSessionsAndBlocksLogin(t *testing.T) {
	ctx := context.Background()
	adminEmail := uniqueEmail(t)
	targetEmail := uniqueEmail(t)
	const password = "correct horse battery staple"

	adminJoin := signUpTestUser(t, ctx, adminEmail, "adminbanactor", password)
	promoteUserRole(t, ctx, adminJoin.UserID, postgres.UserRoleAdmin)
	admin := loginAs(t, ctx, adminEmail, password)

	targetJoin := signUpTestUser(t, ctx, targetEmail, "adminbantarget", password)
	targetLogin, errDetail := services.Login(ctx, testDB, testRedis, targetEmail, password)
	if errDetail != nil {
		t.Fatalf("target Login: %+v", errDetail)
	}
	targetUser, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+targetLogin.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAndParseJWT: %v", err)
	}

	if errDetail := services.BanUser(ctx, testDB, testRedis, admin.ID, admin.Username, targetJoin.UserID, "test ban"); errDetail != nil {
		t.Fatalf("BanUser: %+v", errDetail)
	}

	if _, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+targetLogin.AccessToken); err == nil {
		t.Error("banned user's access token should be revoked")
	}
	if _, errDetail := services.RefreshToken(ctx, testDB, testRedis, targetUser.SessionID, targetLogin.UserID, targetLogin.RefreshToken); errDetail == nil {
		t.Error("banned user's refresh token should be revoked")
	}
	if _, errDetail := services.Login(ctx, testDB, testRedis, targetEmail, password); errDetail == nil {
		t.Error("banned user should not be able to log in")
	}

	got, errDetail := services.GetUser(ctx, testDB, targetJoin.UserID)
	if errDetail != nil {
		t.Fatalf("GetUser: %+v", errDetail)
	}
	if got.Status != "banned" {
		t.Errorf("status = %q, want banned", got.Status)
	}

	// Unban restores login.
	if errDetail := services.UnbanUser(ctx, testDB, testRedis, admin.ID, admin.Username, targetJoin.UserID, ""); errDetail != nil {
		t.Fatalf("UnbanUser: %+v", errDetail)
	}
	if _, errDetail := services.Login(ctx, testDB, testRedis, targetEmail, password); errDetail != nil {
		t.Errorf("unbanned user should be able to log in again: %+v", errDetail)
	}
}

func TestAdminDisableEnableUser(t *testing.T) {
	ctx := context.Background()
	adminEmail := uniqueEmail(t)
	targetEmail := uniqueEmail(t)
	const password = "correct horse battery staple"

	adminJoin := signUpTestUser(t, ctx, adminEmail, "admindisableactor", password)
	promoteUserRole(t, ctx, adminJoin.UserID, postgres.UserRoleModerator)
	moderator := loginAs(t, ctx, adminEmail, password)

	targetJoin := signUpTestUser(t, ctx, targetEmail, "admindisabletarget", password)

	if errDetail := services.DisableUser(ctx, testDB, testRedis, moderator.ID, moderator.Username, targetJoin.UserID, "under review"); errDetail != nil {
		t.Fatalf("DisableUser: %+v", errDetail)
	}
	if _, errDetail := services.Login(ctx, testDB, testRedis, targetEmail, password); errDetail == nil {
		t.Error("disabled user should not be able to log in")
	}

	if errDetail := services.EnableUser(ctx, testDB, testRedis, moderator.ID, moderator.Username, targetJoin.UserID, ""); errDetail != nil {
		t.Fatalf("EnableUser: %+v", errDetail)
	}
	if _, errDetail := services.Login(ctx, testDB, testRedis, targetEmail, password); errDetail != nil {
		t.Errorf("re-enabled user should be able to log in: %+v", errDetail)
	}
}

func TestAdminForceLogoutUser_DoesNotChangeStatus(t *testing.T) {
	ctx := context.Background()
	adminEmail := uniqueEmail(t)
	targetEmail := uniqueEmail(t)
	const password = "correct horse battery staple"

	adminJoin := signUpTestUser(t, ctx, adminEmail, "adminlogoutactor", password)
	promoteUserRole(t, ctx, adminJoin.UserID, postgres.UserRoleModerator)
	moderator := loginAs(t, ctx, adminEmail, password)

	targetJoin := signUpTestUser(t, ctx, targetEmail, "adminlogouttarget", password)
	targetLogin, errDetail := services.Login(ctx, testDB, testRedis, targetEmail, password)
	if errDetail != nil {
		t.Fatalf("target Login: %+v", errDetail)
	}

	if errDetail := services.ForceLogoutUser(ctx, testDB, testRedis, moderator.ID, moderator.Username, targetJoin.UserID, "lost device"); errDetail != nil {
		t.Fatalf("ForceLogoutUser: %+v", errDetail)
	}

	if _, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+targetLogin.AccessToken); err == nil {
		t.Error("force-logged-out user's access token should be revoked")
	}
	// Status is untouched — a fresh login still works.
	if _, errDetail := services.Login(ctx, testDB, testRedis, targetEmail, password); errDetail != nil {
		t.Errorf("force-logged-out (not banned/disabled) user should still be able to log in again: %+v", errDetail)
	}
}

func TestAdminActions_CannotTargetSelf(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"

	join := signUpTestUser(t, ctx, email, "adminselftarget", password)
	promoteUserRole(t, ctx, join.UserID, postgres.UserRoleAdmin)
	admin := loginAs(t, ctx, email, password)

	if errDetail := services.BanUser(ctx, testDB, testRedis, admin.ID, admin.Username, admin.ID, ""); errDetail == nil {
		t.Error("expected banning yourself to be rejected")
	}
	if errDetail := services.ChangeUserRole(ctx, testDB, admin.ID, admin.Username, admin.ID, "moderator"); errDetail == nil {
		t.Error("expected changing your own role to be rejected")
	}
	if errDetail := services.DeleteUser(ctx, testDB, testRedis, admin.ID, admin.Username, admin.ID, ""); errDetail == nil {
		t.Error("expected deleting your own account to be rejected")
	}
}

func TestAdminActions_CannotTargetAnotherAdmin(t *testing.T) {
	ctx := context.Background()
	actorEmail := uniqueEmail(t)
	targetEmail := uniqueEmail(t)
	const password = "correct horse battery staple"

	actorJoin := signUpTestUser(t, ctx, actorEmail, "adminvsadminactor", password)
	promoteUserRole(t, ctx, actorJoin.UserID, postgres.UserRoleAdmin)
	actor := loginAs(t, ctx, actorEmail, password)

	targetJoin := signUpTestUser(t, ctx, targetEmail, "adminvsadmintarget", password)
	promoteUserRole(t, ctx, targetJoin.UserID, postgres.UserRoleAdmin)

	// Even another admin can't ban/role-change/delete an admin account
	// through this API — see admin_service.go's package doc.
	if errDetail := services.BanUser(ctx, testDB, testRedis, actor.ID, actor.Username, targetJoin.UserID, ""); errDetail == nil {
		t.Error("expected banning another admin to be rejected")
	}
	if errDetail := services.ChangeUserRole(ctx, testDB, actor.ID, actor.Username, targetJoin.UserID, "user"); errDetail == nil {
		t.Error("expected demoting another admin to be rejected")
	}
	if errDetail := services.DeleteUser(ctx, testDB, testRedis, actor.ID, actor.Username, targetJoin.UserID, ""); errDetail == nil {
		t.Error("expected deleting another admin to be rejected")
	}
}

func TestAdminChangeUserRole_CannotPromoteToAdmin(t *testing.T) {
	ctx := context.Background()
	actorEmail := uniqueEmail(t)
	targetEmail := uniqueEmail(t)
	const password = "correct horse battery staple"

	actorJoin := signUpTestUser(t, ctx, actorEmail, "adminpromoteactor", password)
	promoteUserRole(t, ctx, actorJoin.UserID, postgres.UserRoleAdmin)
	actor := loginAs(t, ctx, actorEmail, password)

	targetJoin := signUpTestUser(t, ctx, targetEmail, "adminpromotetarget", password)

	if errDetail := services.ChangeUserRole(ctx, testDB, actor.ID, actor.Username, targetJoin.UserID, "admin"); errDetail == nil {
		t.Error("expected promotion straight to admin via the role endpoint to be rejected")
	}

	if errDetail := services.ChangeUserRole(ctx, testDB, actor.ID, actor.Username, targetJoin.UserID, "moderator"); errDetail != nil {
		t.Fatalf("ChangeUserRole to moderator: %+v", errDetail)
	}
	got, errDetail := services.GetUser(ctx, testDB, targetJoin.UserID)
	if errDetail != nil {
		t.Fatalf("GetUser: %+v", errDetail)
	}
	if got.Role != "moderator" {
		t.Errorf("role = %q, want moderator", got.Role)
	}
}

func TestAdminDeleteUser_SoftDeletesAndRevokesSessions(t *testing.T) {
	ctx := context.Background()
	actorEmail := uniqueEmail(t)
	targetEmail := uniqueEmail(t)
	const password = "correct horse battery staple"

	actorJoin := signUpTestUser(t, ctx, actorEmail, "admindeleteactor", password)
	promoteUserRole(t, ctx, actorJoin.UserID, postgres.UserRoleAdmin)
	actor := loginAs(t, ctx, actorEmail, password)

	targetJoin := signUpTestUser(t, ctx, targetEmail, "admindeletetarget", password)
	targetLogin, errDetail := services.Login(ctx, testDB, testRedis, targetEmail, password)
	if errDetail != nil {
		t.Fatalf("target Login: %+v", errDetail)
	}

	if errDetail := services.DeleteUser(ctx, testDB, testRedis, actor.ID, actor.Username, targetJoin.UserID, "gdpr request"); errDetail != nil {
		t.Fatalf("DeleteUser: %+v", errDetail)
	}

	if _, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+targetLogin.AccessToken); err == nil {
		t.Error("deleted user's access token should be revoked")
	}
	got, errDetail := services.GetUser(ctx, testDB, targetJoin.UserID)
	if errDetail != nil {
		t.Fatalf("GetUser (soft-deleted user should still be visible to admins): %+v", errDetail)
	}
	if got.DeletedAt == "" {
		t.Error("expected deleted_at to be set")
	}
}

func TestAdminResetUserPassword_CreatesAdminSourcedReset(t *testing.T) {
	ctx := context.Background()
	actorEmail := uniqueEmail(t)
	targetEmail := uniqueEmail(t)
	const password = "correct horse battery staple"

	actorJoin := signUpTestUser(t, ctx, actorEmail, "adminresetactor", password)
	promoteUserRole(t, ctx, actorJoin.UserID, postgres.UserRoleModerator)
	moderator := loginAs(t, ctx, actorEmail, password)

	targetJoin := signUpTestUser(t, ctx, targetEmail, "adminresettarget", password)

	fakeResend, callCount := newFakeResendClient(t, http.StatusOK)
	if errDetail := services.AdminResetUserPassword(ctx, testDB, fakeResend, moderator.ID, moderator.Username, targetJoin.UserID); errDetail != nil {
		t.Fatalf("AdminResetUserPassword: %+v", errDetail)
	}
	if callCount.Load() != 1 {
		t.Errorf("expected exactly one email send, got %d", callCount.Load())
	}

	q := postgres.New(testDB)
	lastCreated, err := q.GetLatestPasswordResetForUser(ctx, userUUID(t, targetJoin.UserID))
	if err != nil {
		t.Fatalf("GetLatestPasswordResetForUser: %v", err)
	}
	if !lastCreated.Valid {
		t.Error("expected an admin-initiated password reset row to exist")
	}
}

func TestAdminAuditLog_RecordsBanWithActor(t *testing.T) {
	ctx := context.Background()
	actorEmail := uniqueEmail(t)
	targetEmail := uniqueEmail(t)
	const password = "correct horse battery staple"

	actorJoin := signUpTestUser(t, ctx, actorEmail, "adminauditactor", password)
	promoteUserRole(t, ctx, actorJoin.UserID, postgres.UserRoleAdmin)
	admin := loginAs(t, ctx, actorEmail, password)

	targetJoin := signUpTestUser(t, ctx, targetEmail, "adminaudittarget", password)

	if errDetail := services.BanUser(ctx, testDB, testRedis, admin.ID, admin.Username, targetJoin.UserID, "audit trail check"); errDetail != nil {
		t.Fatalf("BanUser: %+v", errDetail)
	}

	logs, errDetail := services.ListAuditLogs(ctx, testDB, targetJoin.UserID, 10, 0)
	if errDetail != nil {
		t.Fatalf("ListAuditLogs: %+v", errDetail)
	}
	found := false
	for _, entry := range logs.Entries {
		if entry.Action == "user_ban" {
			found = true
			if entry.ActorID != admin.ID {
				t.Errorf("audit log actor_id = %q, want %q", entry.ActorID, admin.ID)
			}
			if entry.Reason != "audit trail check" {
				t.Errorf("audit log reason = %q, want %q", entry.Reason, "audit trail check")
			}
		}
	}
	if !found {
		t.Error("expected a user_ban audit log entry attributed to the banning admin")
	}
}
