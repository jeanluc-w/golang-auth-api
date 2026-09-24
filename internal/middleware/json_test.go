package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auth-api/config"
)

func init() {
	if config.Loaded == nil {
		config.Loaded = &config.Config{Env: "test"}
	}
}

func TestJSONMiddleware_RejectsNonJSONBody(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not run for a rejected content type")
	})
	handler := JSONMiddleware(next)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("plain text"))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnsupportedMediaType)
	}
}

func TestJSONMiddleware_AllowsJSONBody(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	handler := JSONMiddleware(next)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if !called {
		t.Error("expected next handler to run for a JSON POST body")
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("response Content-Type = %q, want application/json", got)
	}
}

func TestJSONMiddleware_GetIsNotContentTypeGated(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	handler := JSONMiddleware(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if !called {
		t.Error("expected GET requests to pass through regardless of Content-Type")
	}
}
