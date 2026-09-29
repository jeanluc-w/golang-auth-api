package integration

import (
	"context"
	"testing"

	"auth-api/internal/auth"
	"auth-api/internal/services"
)

// TestChangePassword_FullFlow_RevokesOtherSessionsOnly is the main
// end-to-end test: after a change, the old password must stop working, the
// new one must work, the session that MADE the change must still be valid
// (unlike a reset), and every OTHER session must be dead in both Postgres
// and Redis.
func TestChangePassword_FullFlow_RevokesOtherSessionsOnly(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const oldPassword = "correct horse battery staple"
	const newPassword = "new correct horse battery staple"
	signUpTestUser(t, ctx, email, "changepwflowuser", oldPassword)

	// Two independent sessions, as if logged in on two devices.
	deviceA, errDetail := services.Login(ctx, testDB, testRedis, email, oldPassword)
	if errDetail != nil {
		t.Fatalf("Login (device A): %+v", errDetail)
	}
	deviceB, errDetail := services.Login(ctx, testDB, testRedis, email, oldPassword)
	if errDetail != nil {
		t.Fatalf("Login (device B): %+v", errDetail)
	}
	userA, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+deviceA.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAndParseJWT (device A): %v", err)
	}
	userB, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+deviceB.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAndParseJWT (device B): %v", err)
	}

	// Change password FROM device A.
	if errDetail := services.ChangePassword(ctx, testDB, testRedis, userA.ID, userA.SessionID, oldPassword, newPassword, newPassword); errDetail != nil {
		t.Fatalf("ChangePassword: %+v", errDetail)
	}

	if _, errDetail := services.Login(ctx, testDB, testRedis, email, oldPassword); errDetail == nil {
		t.Error("old password still works after change")
	}
	if _, errDetail := services.Login(ctx, testDB, testRedis, email, newPassword); errDetail != nil {
		t.Errorf("new password doesn't work after change: %+v", errDetail)
	}

	// Device A's own access token (the one that made the change) must
	// still be valid.
	if _, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+deviceA.AccessToken); err != nil {
		t.Errorf("device A's access token was revoked, but it made the change and should survive: %v", err)
	}
	if _, errDetail := services.RefreshToken(ctx, testDB, testRedis, userA.SessionID, deviceA.UserID, deviceA.RefreshToken); errDetail != nil {
		t.Errorf("device A's refresh token should still work: %+v", errDetail)
	}

	// Device B must be fully revoked — both the Redis-checked access token
	// and the Postgres-checked refresh token.
	if _, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+deviceB.AccessToken); err == nil {
		t.Error("device B's access token still valid after a password change elsewhere")
	}
	if _, errDetail := services.RefreshToken(ctx, testDB, testRedis, userB.SessionID, deviceB.UserID, deviceB.RefreshToken); errDetail == nil {
		t.Error("device B's refresh token still works after a password change elsewhere")
	}
}

func TestChangePassword_WrongCurrentPasswordRejected(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"
	signUpTestUser(t, ctx, email, "changepwwrongcurrent", password)

	login, errDetail := services.Login(ctx, testDB, testRedis, email, password)
	if errDetail != nil {
		t.Fatalf("Login: %+v", errDetail)
	}
	user, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+login.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAndParseJWT: %v", err)
	}

	if errDetail := services.ChangePassword(ctx, testDB, testRedis, user.ID, user.SessionID, "the wrong password entirely", "some new password!", "some new password!"); errDetail == nil {
		t.Error("expected an incorrect current password to be rejected")
	}
}

func TestChangePassword_NewMatchesCurrentRejected(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"
	signUpTestUser(t, ctx, email, "changepwsamepass", password)

	login, errDetail := services.Login(ctx, testDB, testRedis, email, password)
	if errDetail != nil {
		t.Fatalf("Login: %+v", errDetail)
	}
	user, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+login.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAndParseJWT: %v", err)
	}

	if errDetail := services.ChangePassword(ctx, testDB, testRedis, user.ID, user.SessionID, password, password, password); errDetail == nil {
		t.Error("expected changing to the same password to be rejected")
	}
}

func TestChangePassword_MismatchedConfirmationRejected(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"
	signUpTestUser(t, ctx, email, "changepwmismatch", password)

	login, errDetail := services.Login(ctx, testDB, testRedis, email, password)
	if errDetail != nil {
		t.Fatalf("Login: %+v", errDetail)
	}
	user, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+login.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAndParseJWT: %v", err)
	}

	if errDetail := services.ChangePassword(ctx, testDB, testRedis, user.ID, user.SessionID, password, "new password one", "a different new password"); errDetail == nil {
		t.Error("expected mismatched new/confirm passwords to be rejected")
	}
}
