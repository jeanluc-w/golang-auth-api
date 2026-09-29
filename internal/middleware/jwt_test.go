package middleware

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth-api/config"
	"auth-api/internal/auth"
	"auth-api/internal/entities"
	"auth-api/internal/server"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

// setTestConfig installs a config.Config with a fresh Ed25519 keypair for
// the duration of a test, mirroring internal/auth's helper of the same
// purpose (unexported per-package, so it's duplicated rather than shared).
func setTestConfig(t *testing.T) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	config.Loaded = &config.Config{
		Env:           "test",
		JWTPrivateKey: priv,
		JWTPublicKey:  pub,
		JWTAlgorithm:  jwt.SigningMethodEdDSA,
	}
}

func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	mr := miniredis.RunT(t)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

func TestIsAlternateRoute(t *testing.T) {
	routes := []string{"/a", "/b"}
	if !isAlternateRoute("/a", routes) {
		t.Error("expected /a to match")
	}
	if isAlternateRoute("/c", routes) {
		t.Error("expected /c not to match")
	}
	if isAlternateRoute("/a/sub", routes) {
		t.Error("expected isAlternateRoute to require an exact match, not a prefix")
	}
}

func TestJWTMiddleware_OpenRoute_NoAuthRequired(t *testing.T) {
	setTestConfig(t)
	rdb := newTestRedis(t)
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	handler := JWTMiddleware(rdb)(next)

	req := httptest.NewRequest(http.MethodGet, server.V1_HealthCheck, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("expected an open route to reach the next handler without any Authorization header")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestJWTMiddleware_ProtectedRoute_RejectsMissingOrBadToken(t *testing.T) {
	setTestConfig(t)
	rdb := newTestRedis(t)
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	handler := JWTMiddleware(rdb)(next)

	cases := []string{"", "Bearer not-a-jwt", "Basic dXNlcjpwYXNz"}
	for _, authHeader := range cases {
		called = false
		req := httptest.NewRequest(http.MethodGet, "/some/protected/route", nil)
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if called {
			t.Errorf("authHeader %q: expected the next handler NOT to be called", authHeader)
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("authHeader %q: status = %d, want 401", authHeader, w.Code)
		}
	}
}

func TestJWTMiddleware_ProtectedRoute_ValidTokenAttachesUser(t *testing.T) {
	setTestConfig(t)
	rdb := newTestRedis(t)
	var gotUser *entities.UserContext
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, _ = r.Context().Value(entities.UserContextKey).(*entities.UserContext)
	})
	handler := JWTMiddleware(rdb)(next)

	pair, err := auth.GenerateUserTokens(context.Background(), rdb, "user-1", "alice", "user", time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("GenerateUserTokens: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/some/protected/route", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if gotUser == nil || gotUser.ID != "user-1" || gotUser.SessionID != pair.SessionID {
		t.Errorf("unexpected user context: %+v", gotUser)
	}
}

func TestJWTMiddleware_TemporaryJWTRoute(t *testing.T) {
	setTestConfig(t)
	rdb := newTestRedis(t)
	var gotEmail string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEmail, _ = r.Context().Value(entities.EmailFromTempJWTContextKey).(string)
	})
	handler := JWTMiddleware(rdb)(next)

	token, err := auth.GenerateTemporaryJWT(context.Background(), rdb, "joiner@example.com", time.Hour)
	if err != nil {
		t.Fatalf("GenerateTemporaryJWT: %v", err)
	}

	t.Run("valid temporary token is accepted on a temp-JWT route", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, server.TemporaryJWTRoutes[0], nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		if gotEmail != "joiner@example.com" {
			t.Errorf("email in context = %q, want joiner@example.com", gotEmail)
		}
	})

	t.Run("a normal access token is rejected on a temp-JWT route", func(t *testing.T) {
		pair, err := auth.GenerateUserTokens(context.Background(), rdb, "user-1", "alice", "user", time.Hour, time.Hour)
		if err != nil {
			t.Fatalf("GenerateUserTokens: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, server.TemporaryJWTRoutes[0], nil)
		req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 (a normal access token must not work on a joiner-only route)", w.Code)
		}
	})
}

func TestJWTMiddleware_RefreshTokenRoute_AllowsExpiredAccessToken(t *testing.T) {
	setTestConfig(t)
	rdb := newTestRedis(t)
	var gotSessionID, gotUserID string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSessionID, _ = r.Context().Value(entities.SessionIDFromExpiredJWTContextKey).(string)
		gotUserID, _ = r.Context().Value(entities.UserIDFromExpiredJWTContextKey).(string)
	})
	handler := JWTMiddleware(rdb)(next)

	// A token that expired an hour ago must still be usable to *identify*
	// the session on the refresh route — that's the whole point of the
	// refresh flow. Generate one directly with GenerateUserTokens (TTL in
	// the past) rather than waiting for a real one to expire.
	pair, err := auth.GenerateUserTokens(context.Background(), rdb, "user-1", "alice", "user", -time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("GenerateUserTokens: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, server.V1_RefreshToken, nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (an expired access token must be accepted on the refresh route)", w.Code)
	}
	if gotSessionID != pair.SessionID || gotUserID != "user-1" {
		t.Errorf("got sessionID=%q userID=%q, want %q/%q", gotSessionID, gotUserID, pair.SessionID, "user-1")
	}
}
