package auth

import (
	"context"
	"strings"
	"testing"
	"time"
)

// These tests cover the jwt.go functions that touch Redis (session
// bookkeeping), using the same miniredis-backed newTestRedis helper as
// session_test.go. They were previously exercised only by the Docker-gated
// integration suite; unit-testing them here catches regressions in the core
// token-issuance/verification logic without needing Postgres or Docker at
// all.

func TestGenerateUserTokens(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")
	ctx := context.Background()
	rdb := newTestRedis(t)

	pair, err := GenerateUserTokens(ctx, rdb, "user-1", "alice", "user", time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateUserTokens: %v", err)
	}
	if pair.SessionID == "" {
		t.Fatal("expected a non-empty session ID")
	}
	if pair.RefreshToken == "" || pair.AccessToken == "" {
		t.Fatal("expected both tokens to be populated")
	}

	// The access token must parse back to the same user/session.
	claims, err := parseJWT("Bearer "+pair.AccessToken, false)
	if err != nil {
		t.Fatalf("parseJWT on generated access token: %v", err)
	}
	if claims.UserID != "user-1" || claims.Username != "alice" || claims.ID != pair.SessionID {
		t.Errorf("unexpected claims: %+v", claims)
	}

	// The session must be recorded in Redis so VerifyAndParseJWT can find it.
	exists, err := rdb.Exists(ctx, "session:"+pair.SessionID).Result()
	if err != nil {
		t.Fatalf("Exists(session): %v", err)
	}
	if exists != 1 {
		t.Error("expected GenerateUserTokens to record the session in Redis")
	}

	// Only the refresh token's hash is stored, never the raw value.
	stored, err := rdb.Get(ctx, "refresh:"+pair.SessionID).Result()
	if err != nil {
		t.Fatalf("Get(refresh): %v", err)
	}
	if stored == pair.RefreshToken {
		t.Error("expected only the refresh token's hash to be stored, not the raw token")
	}
	if stored != HashRefreshToken(pair.RefreshToken) {
		t.Error("stored refresh value does not match HashRefreshToken(raw)")
	}
}

func TestGenerateUserTokens_NilRedisClient(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")
	if _, err := GenerateUserTokens(context.Background(), nil, "user-1", "alice", "user", time.Hour, time.Hour); err == nil {
		t.Error("expected an error with a nil Redis client")
	}
}

func TestRotateSessionTokens(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")
	ctx := context.Background()
	rdb := newTestRedis(t)

	original, err := GenerateUserTokens(ctx, rdb, "user-1", "alice", "user", time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateUserTokens: %v", err)
	}

	rotated, err := RotateSessionTokens(ctx, rdb, original.SessionID, "user-1", "alice", "user", time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("RotateSessionTokens: %v", err)
	}

	if rotated.SessionID != original.SessionID {
		t.Errorf("RotateSessionTokens changed the session ID: got %q, want %q", rotated.SessionID, original.SessionID)
	}
	// Note: the access token itself may be byte-identical to the original if
	// both were signed within the same wall-clock second, since JWT
	// timestamps only have second resolution and every other claim
	// (session/user/role) is unchanged by rotation — that's expected, not a
	// bug. The refresh token, being randomly generated rather than derived
	// from claims, always differs.
	if rotated.RefreshToken == original.RefreshToken {
		t.Error("expected a freshly generated refresh token, not the same one")
	}

	// The old refresh token's hash must no longer validate — rotation
	// overwrites the session's Redis entry rather than appending to it.
	stored, err := rdb.Get(ctx, "refresh:"+original.SessionID).Result()
	if err != nil {
		t.Fatalf("Get(refresh): %v", err)
	}
	if stored == HashRefreshToken(original.RefreshToken) {
		t.Error("expected rotation to overwrite the stored refresh hash")
	}
	if stored != HashRefreshToken(rotated.RefreshToken) {
		t.Error("stored refresh hash does not match the newly rotated token")
	}
}

func TestGenerateTemporaryJWT(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")
	ctx := context.Background()
	rdb := newTestRedis(t)

	token, err := GenerateTemporaryJWT(ctx, rdb, "someone@example.com", 10*time.Minute)
	if err != nil {
		t.Fatalf("GenerateTemporaryJWT: %v", err)
	}

	email, id, err := VerifyAndParseTemporaryJWT(ctx, rdb, "Bearer "+token)
	if err != nil {
		t.Fatalf("VerifyAndParseTemporaryJWT: %v", err)
	}
	if email != "someone@example.com" {
		t.Errorf("email = %q, want someone@example.com", email)
	}
	if id == "" {
		t.Error("expected a non-empty session/JTI")
	}
}

func TestVerifyAndParseJWT(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")
	ctx := context.Background()

	t.Run("valid session succeeds", func(t *testing.T) {
		rdb := newTestRedis(t)
		pair, err := GenerateUserTokens(ctx, rdb, "user-1", "alice", "user", time.Hour, time.Hour)
		if err != nil {
			t.Fatalf("GenerateUserTokens: %v", err)
		}
		user, err := VerifyAndParseJWT(ctx, rdb, "Bearer "+pair.AccessToken)
		if err != nil {
			t.Fatalf("VerifyAndParseJWT: %v", err)
		}
		if user.ID != "user-1" || user.Username != "alice" || user.SessionID != pair.SessionID {
			t.Errorf("unexpected user context: %+v", user)
		}
	})

	t.Run("revoked session is rejected", func(t *testing.T) {
		rdb := newTestRedis(t)
		pair, err := GenerateUserTokens(ctx, rdb, "user-1", "alice", "user", time.Hour, time.Hour)
		if err != nil {
			t.Fatalf("GenerateUserTokens: %v", err)
		}
		// Simulate logout/revocation: the session key is gone, but the JWT
		// itself is still cryptographically valid and unexpired.
		if err := rdb.Del(ctx, "session:"+pair.SessionID).Err(); err != nil {
			t.Fatalf("Del: %v", err)
		}
		if _, err := VerifyAndParseJWT(ctx, rdb, "Bearer "+pair.AccessToken); err == nil {
			t.Error("expected a revoked session to be rejected even with a still-valid JWT")
		}
	})

	t.Run("temporary token is rejected on the normal path", func(t *testing.T) {
		rdb := newTestRedis(t)
		token, err := GenerateTemporaryJWT(ctx, rdb, "someone@example.com", time.Hour)
		if err != nil {
			t.Fatalf("GenerateTemporaryJWT: %v", err)
		}
		if _, err := VerifyAndParseJWT(ctx, rdb, "Bearer "+token); err == nil {
			t.Error("expected a joiner-role token to be rejected by VerifyAndParseJWT")
		}
	})

	t.Run("malformed header is rejected", func(t *testing.T) {
		rdb := newTestRedis(t)
		if _, err := VerifyAndParseJWT(ctx, rdb, "not-a-bearer-token"); err == nil {
			t.Error("expected a malformed Authorization header to be rejected")
		}
	})
}

func TestVerifyAndParseTemporaryJWT_RejectsNormalToken(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")
	ctx := context.Background()
	rdb := newTestRedis(t)

	pair, err := GenerateUserTokens(ctx, rdb, "user-1", "alice", "user", time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("GenerateUserTokens: %v", err)
	}
	if _, _, err := VerifyAndParseTemporaryJWT(ctx, rdb, "Bearer "+pair.AccessToken); err == nil {
		t.Error("expected a normal access token to be rejected by VerifyAndParseTemporaryJWT")
	}
}

func TestVerifyAndParseTemporaryJWT_RevokedSession(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")
	ctx := context.Background()
	rdb := newTestRedis(t)

	token, err := GenerateTemporaryJWT(ctx, rdb, "someone@example.com", time.Hour)
	if err != nil {
		t.Fatalf("GenerateTemporaryJWT: %v", err)
	}
	_, id, err := VerifyAndParseTemporaryJWT(ctx, rdb, "Bearer "+token)
	if err != nil {
		t.Fatalf("VerifyAndParseTemporaryJWT: %v", err)
	}
	if err := DeleteTemporarySession(ctx, id, rdb); err != nil {
		t.Fatalf("DeleteTemporarySession: %v", err)
	}
	if _, _, err := VerifyAndParseTemporaryJWT(ctx, rdb, "Bearer "+token); err == nil {
		t.Error("expected a revoked temporary session to be rejected")
	}
}

func TestRandomToken(t *testing.T) {
	a, err := randomToken(32)
	if err != nil {
		t.Fatalf("randomToken: %v", err)
	}
	b, err := randomToken(32)
	if err != nil {
		t.Fatalf("randomToken: %v", err)
	}
	if a == b {
		t.Error("expected two random tokens not to collide")
	}
	if strings.ContainsAny(a, "+/=") {
		t.Errorf("expected base64url (no +, /, or = padding) encoding, got %q", a)
	}
}

func TestGenerateAndStoreRefresh_ExpiresWithTTL(t *testing.T) {
	setTestConfig(t, "unused:"+testPepper(1), "unused")
	ctx := context.Background()
	rdb := newTestRedis(t)

	pair, err := GenerateUserTokens(ctx, rdb, "user-1", "alice", "user", time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateUserTokens: %v", err)
	}
	ttl, err := rdb.TTL(ctx, "refresh:"+pair.SessionID).Result()
	if err != nil {
		t.Fatalf("TTL: %v", err)
	}
	if ttl <= 0 || ttl > 5*time.Minute {
		t.Errorf("refresh TTL = %v, want roughly 5 minutes", ttl)
	}
}
