package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth-api/config"
)

func TestTimeoutMiddleware_AllowsFastRequests(t *testing.T) {
	config.Loaded = &config.Config{RequestTimeout: 50 * time.Millisecond}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := TimeoutMiddleware(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for a request well under the timeout", w.Code)
	}
}

func TestTimeoutMiddleware_CutsOffSlowRequests(t *testing.T) {
	config.Loaded = &config.Config{RequestTimeout: 10 * time.Millisecond}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	handler := TimeoutMiddleware(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 once the handler exceeds the timeout", w.Code)
	}
	if got := w.Body.String(); got != `{"error":"request timeout"}` {
		t.Errorf("body = %q, want the JSON timeout message", got)
	}
}
