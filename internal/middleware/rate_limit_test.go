package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth-api/internal/entities"

	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

func newTestLimiter(limit int64) *limiter.Limiter {
	store := memory.NewStore()
	return limiter.New(store, limiter.Rate{Period: time.Minute, Limit: limit})
}

func TestClientIP(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4:5678":   "1.2.3.4",
		"[::1]:8080":     "::1",
		"no-port-at-all": "no-port-at-all",
		"192.168.0.1:0":  "192.168.0.1",
	}
	for remoteAddr, want := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remoteAddr
		if got := clientIP(req); got != want {
			t.Errorf("clientIP(%q) = %q, want %q", remoteAddr, got, want)
		}
	}
}

func TestRateLimitMiddleware_AllowsUnderLimitAndBlocksOver(t *testing.T) {
	l := newTestLimiter(2)
	called := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++ })
	handler := RateLimitMiddleware(l)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1111"

	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, w.Code)
		}
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("3rd request: status = %d, want 429", w.Code)
	}
	if called != 2 {
		t.Errorf("next handler called %d times, want 2 (3rd request should have been blocked)", called)
	}
}

func TestRateLimitMiddleware_DifferentIPsAreIndependent(t *testing.T) {
	l := newTestLimiter(1)
	handler := RateLimitMiddleware(l)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	for _, addr := range []string{"10.0.0.1:1", "10.0.0.2:1"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = addr
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("first request from %s: status = %d, want 200", addr, w.Code)
		}
	}
}

func TestUserRateLimitMiddleware_NoUserPassesThroughUnlimited(t *testing.T) {
	l := newTestLimiter(1) // limit of 1, but should never be consulted without a user
	called := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++ })
	handler := UserRateLimitMiddleware(l)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d with no user in context: status = %d, want 200 (should never be rate-limited)", i+1, w.Code)
		}
	}
	if called != 5 {
		t.Errorf("next handler called %d times, want 5", called)
	}
}

func TestUserRateLimitMiddleware_LimitsPerUser(t *testing.T) {
	l := newTestLimiter(2)
	handler := UserRateLimitMiddleware(l)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	ctx := context.WithValue(context.Background(), entities.UserContextKey, &entities.UserContext{ID: "user-1"})
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)

	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, w.Code)
		}
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("3rd request: status = %d, want 429", w.Code)
	}
}

func TestUserRateLimitMiddleware_DifferentUsersAreIndependent(t *testing.T) {
	l := newTestLimiter(1)
	handler := UserRateLimitMiddleware(l)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	// Exhaust user-1's budget.
	ctx1 := context.WithValue(context.Background(), entities.UserContextKey, &entities.UserContext{ID: "user-1"})
	req1 := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx1)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req1)
	if w.Code != http.StatusOK {
		t.Fatalf("user-1 first request: status = %d, want 200", w.Code)
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req1)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("user-1 second request: status = %d, want 429 (budget should be exhausted)", w.Code)
	}

	// user-2 must be unaffected by user-1 being rate-limited — this is the
	// whole point of per-user (rather than shared-IP) keying.
	ctx2 := context.WithValue(context.Background(), entities.UserContextKey, &entities.UserContext{ID: "user-2"})
	req2 := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx2)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req2)
	if w.Code != http.StatusOK {
		t.Errorf("user-2 first request: status = %d, want 200 (should have its own budget)", w.Code)
	}
}
