package auth

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newTestRedis returns a real *redis.Client backed by an in-memory
// miniredis instance, auto-closed via t.Cleanup. This gives fast,
// Docker-free unit tests for Redis-touching code using the exact same
// client type production code uses.
func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	mr := miniredis.RunT(t)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

func TestIsValidSession(t *testing.T) {
	ctx := context.Background()
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)

	t.Run("present and not expired", func(t *testing.T) {
		rdb := newTestRedis(t)
		if err := GenerateSession(ctx, "sess-1", future, rdb); err != nil {
			t.Fatalf("GenerateSession: %v", err)
		}
		if !IsValidSession(ctx, "sess-1", future, rdb) {
			t.Error("expected a freshly generated, unexpired session to be valid")
		}
	})

	t.Run("absent", func(t *testing.T) {
		rdb := newTestRedis(t)
		if IsValidSession(ctx, "no-such-session", future, rdb) {
			t.Error("expected a session with no Redis entry to be invalid")
		}
	})

	t.Run("exp already passed", func(t *testing.T) {
		rdb := newTestRedis(t)
		if err := GenerateSession(ctx, "sess-2", future, rdb); err != nil {
			t.Fatalf("GenerateSession: %v", err)
		}
		if IsValidSession(ctx, "sess-2", past, rdb) {
			t.Error("expected a session to be invalid once its passed-in expiration is in the past, regardless of the Redis entry")
		}
	})

	t.Run("redis error fails closed", func(t *testing.T) {
		rdb := newTestRedis(t)
		rdb.Close() // force every subsequent call to error
		if IsValidSession(ctx, "sess-3", future, rdb) {
			t.Error("expected a Redis error to fail closed (invalid), not open (valid)")
		}
	})
}

func TestIsValidTemporarySession(t *testing.T) {
	ctx := context.Background()
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)

	t.Run("present and not expired", func(t *testing.T) {
		rdb := newTestRedis(t)
		if err := GenerateTemporarySession(ctx, "temp-1", future, rdb); err != nil {
			t.Fatalf("GenerateTemporarySession: %v", err)
		}
		if !IsValidTemporarySession(ctx, "temp-1", future, rdb) {
			t.Error("expected a freshly generated, unexpired temporary session to be valid")
		}
	})

	t.Run("absent", func(t *testing.T) {
		rdb := newTestRedis(t)
		if IsValidTemporarySession(ctx, "no-such-session", future, rdb) {
			t.Error("expected a temporary session with no Redis entry to be invalid")
		}
	})

	t.Run("exp already passed", func(t *testing.T) {
		rdb := newTestRedis(t)
		if err := GenerateTemporarySession(ctx, "temp-2", future, rdb); err != nil {
			t.Fatalf("GenerateTemporarySession: %v", err)
		}
		if IsValidTemporarySession(ctx, "temp-2", past, rdb) {
			t.Error("expected an expired temporary session to be invalid regardless of the Redis entry")
		}
	})

	t.Run("redis error fails closed", func(t *testing.T) {
		rdb := newTestRedis(t)
		rdb.Close()
		if IsValidTemporarySession(ctx, "temp-3", future, rdb) {
			t.Error("expected a Redis error to fail closed (invalid), not open (valid)")
		}
	})
}

func TestGenerateSession(t *testing.T) {
	ctx := context.Background()

	t.Run("sets key with correct TTL", func(t *testing.T) {
		rdb := newTestRedis(t)
		exp := time.Now().Add(10 * time.Minute)
		if err := GenerateSession(ctx, "sess-ttl", exp, rdb); err != nil {
			t.Fatalf("GenerateSession: %v", err)
		}
		ttl, err := rdb.TTL(ctx, "session:sess-ttl").Result()
		if err != nil {
			t.Fatalf("TTL: %v", err)
		}
		if ttl <= 0 || ttl > 10*time.Minute {
			t.Errorf("TTL = %v, want roughly 10 minutes", ttl)
		}
	})

	t.Run("already-expired exp is a no-op", func(t *testing.T) {
		rdb := newTestRedis(t)
		if err := GenerateSession(ctx, "sess-past", time.Now().Add(-time.Minute), rdb); err != nil {
			t.Fatalf("GenerateSession: %v", err)
		}
		exists, err := rdb.Exists(ctx, "session:sess-past").Result()
		if err != nil {
			t.Fatalf("Exists: %v", err)
		}
		if exists != 0 {
			t.Error("expected no key to be set for an already-expired session")
		}
	})
}

func TestGenerateTemporarySession(t *testing.T) {
	ctx := context.Background()

	t.Run("sets key with correct TTL", func(t *testing.T) {
		rdb := newTestRedis(t)
		exp := time.Now().Add(5 * time.Minute)
		if err := GenerateTemporarySession(ctx, "temp-ttl", exp, rdb); err != nil {
			t.Fatalf("GenerateTemporarySession: %v", err)
		}
		ttl, err := rdb.TTL(ctx, "temporary_session:temp-ttl").Result()
		if err != nil {
			t.Fatalf("TTL: %v", err)
		}
		if ttl <= 0 || ttl > 5*time.Minute {
			t.Errorf("TTL = %v, want roughly 5 minutes", ttl)
		}
	})

	t.Run("already-expired exp is a no-op", func(t *testing.T) {
		rdb := newTestRedis(t)
		if err := GenerateTemporarySession(ctx, "temp-past", time.Now().Add(-time.Minute), rdb); err != nil {
			t.Fatalf("GenerateTemporarySession: %v", err)
		}
		exists, err := rdb.Exists(ctx, "temporary_session:temp-past").Result()
		if err != nil {
			t.Fatalf("Exists: %v", err)
		}
		if exists != 0 {
			t.Error("expected no key to be set for an already-expired temporary session")
		}
	})
}

func TestDeleteTemporarySession(t *testing.T) {
	ctx := context.Background()
	rdb := newTestRedis(t)

	if err := GenerateTemporarySession(ctx, "temp-del", time.Now().Add(time.Hour), rdb); err != nil {
		t.Fatalf("GenerateTemporarySession: %v", err)
	}
	if err := DeleteTemporarySession(ctx, "temp-del", rdb); err != nil {
		t.Fatalf("DeleteTemporarySession: %v", err)
	}
	exists, err := rdb.Exists(ctx, "temporary_session:temp-del").Result()
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists != 0 {
		t.Error("expected the temporary session key to be gone after delete")
	}

	// Deleting an already-absent key is a no-op, not an error.
	if err := DeleteTemporarySession(ctx, "never-existed", rdb); err != nil {
		t.Errorf("DeleteTemporarySession on a missing key returned an error: %v", err)
	}
}

func TestDeleteSession(t *testing.T) {
	ctx := context.Background()
	rdb := newTestRedis(t)

	if err := GenerateSession(ctx, "sess-del", time.Now().Add(time.Hour), rdb); err != nil {
		t.Fatalf("GenerateSession: %v", err)
	}
	if err := rdb.Set(ctx, "refresh:sess-del", "some-hash", time.Hour).Err(); err != nil {
		t.Fatalf("seeding refresh key: %v", err)
	}

	if err := DeleteSession(ctx, "sess-del", rdb); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	for _, key := range []string{"session:sess-del", "refresh:sess-del"} {
		exists, err := rdb.Exists(ctx, key).Result()
		if err != nil {
			t.Fatalf("Exists(%s): %v", key, err)
		}
		if exists != 0 {
			t.Errorf("expected key %q to be gone after DeleteSession", key)
		}
	}

	// No-op, not an error, when neither key exists.
	if err := DeleteSession(ctx, "never-existed", rdb); err != nil {
		t.Errorf("DeleteSession on missing keys returned an error: %v", err)
	}
}
