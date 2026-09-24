package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"auth-api/config"
)

func withTestConfig(env string, allowedOrigins []string) func() {
	prev := config.Loaded
	config.Loaded = &config.Config{Env: env, AllowedOrigins: allowedOrigins}
	return func() { config.Loaded = prev }
}

func TestResponseHeadersMiddleware_DevWildcard(t *testing.T) {
	defer withTestConfig("development", nil)()

	handler := ResponseHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://anything.example.com")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("ACAO = %q, want *", got)
	}
}

func TestResponseHeadersMiddleware_AllowedOriginIsEchoed(t *testing.T) {
	defer withTestConfig("production", []string{"https://app.example.com"})()

	handler := ResponseHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("ACAO = %q, want https://app.example.com", got)
	}
	if got := w.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want Origin", got)
	}
}

func TestResponseHeadersMiddleware_DisallowedOriginGetsNoACAO(t *testing.T) {
	defer withTestConfig("production", []string{"https://app.example.com"})()

	handler := ResponseHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("ACAO = %q, want empty for a disallowed origin", got)
	}
}

func TestResponseHeadersMiddleware_SecurityHeadersAlwaysSet(t *testing.T) {
	defer withTestConfig("production", nil)()

	handler := ResponseHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	for _, h := range []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Strict-Transport-Security",
		"Referrer-Policy",
		"Content-Security-Policy",
	} {
		if w.Header().Get(h) == "" {
			t.Errorf("expected header %s to be set", h)
		}
	}
}

func TestResponseHeadersMiddleware_OptionsPreflightShortCircuits(t *testing.T) {
	defer withTestConfig("production", []string{"https://app.example.com"})()

	called := false
	handler := ResponseHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if called {
		t.Error("expected OPTIONS preflight to short-circuit before the next handler")
	}
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNoContent)
	}
}
