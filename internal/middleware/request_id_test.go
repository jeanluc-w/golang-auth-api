package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"auth-api/internal/entities"
)

func TestRequestIDMiddleware_GeneratesWhenMissing(t *testing.T) {
	var gotFromCtx string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotFromCtx, _ = r.Context().Value(entities.RequestContextKey).(string)
	})
	handler := RequestIDMiddleware(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if gotFromCtx == "" {
		t.Error("expected a generated request id in context")
	}
	if got := w.Header().Get("X-Request-ID"); got == "" || got != gotFromCtx {
		t.Errorf("response header X-Request-ID = %q, want it to match context value %q", got, gotFromCtx)
	}
}

func TestRequestIDMiddleware_ReusesProvidedID(t *testing.T) {
	const provided = "client-supplied-id-123"
	var gotFromCtx string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotFromCtx, _ = r.Context().Value(entities.RequestContextKey).(string)
	})
	handler := RequestIDMiddleware(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", provided)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if gotFromCtx != provided {
		t.Errorf("context request id = %q, want %q", gotFromCtx, provided)
	}
	if got := w.Header().Get("X-Request-ID"); got != provided {
		t.Errorf("response header X-Request-ID = %q, want %q", got, provided)
	}
}
