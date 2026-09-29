package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"auth-api/internal/entities"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestSafe(t *testing.T) {
	get := func(u *entities.UserContext) string { return u.ID }

	if got := safe[entities.UserContext](nil, get); got != "" {
		t.Errorf("safe(nil) = %q, want empty string", got)
	}
	user := &entities.UserContext{ID: "user-1"}
	if got := safe(user, get); got != "user-1" {
		t.Errorf("safe(user) = %q, want user-1", got)
	}
}

func TestLoggerMiddleware_LogsRequestStartAndCompletion(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	// LoggerMiddleware reads rw.Status from an *entities.ResponseWriter, so
	// it must run inside ResponseWriterMiddleware just like in the real
	// stack (see build_handler_stack.go).
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	handler := ResponseWriterMiddleware(LoggerMiddleware(logger)(next))

	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	messages := logs.All()
	if len(messages) != 2 {
		t.Fatalf("got %d log entries, want 2 (start + completion): %+v", len(messages), messages)
	}
	if messages[0].Message != "Processing Request" {
		t.Errorf("first log message = %q, want %q", messages[0].Message, "Processing Request")
	}
	if messages[1].Message != "Request Completed" {
		t.Errorf("second log message = %q, want %q", messages[1].Message, "Request Completed")
	}
	if status, ok := messages[1].ContextMap()["status"].(int64); !ok || status != http.StatusTeapot {
		t.Errorf("completion log status field = %v, want %d", messages[1].ContextMap()["status"], http.StatusTeapot)
	}
}

func TestLoggerMiddleware_RecoversPanicAndReturns500(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})
	handler := ResponseWriterMiddleware(LoggerMiddleware(logger)(next))

	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	w := httptest.NewRecorder()

	// A panicking handler must never escape LoggerMiddleware and crash the
	// server; ServeHTTP itself must return normally.
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 after a recovered panic", w.Code)
	}

	var sawErrorLog bool
	for _, entry := range logs.All() {
		if entry.Message == "Recovered from panic" {
			sawErrorLog = true
		}
	}
	if !sawErrorLog {
		t.Error("expected a \"Recovered from panic\" log entry")
	}
}

func TestLoggerMiddleware_WithoutResponseWriterMiddleware_FallsBack(t *testing.T) {
	// If LoggerMiddleware ever runs without ResponseWriterMiddleware ahead of
	// it (a wiring mistake in BuildHandlerStack), it must still log a
	// completion entry rather than panicking on the type assertion.
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler := LoggerMiddleware(logger)(next)

	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	messages := logs.All()
	if len(messages) != 2 {
		t.Fatalf("got %d log entries, want 2: %+v", len(messages), messages)
	}
	if status, _ := messages[1].ContextMap()["status"].(string); status != "unknown" {
		t.Errorf("fallback completion log status = %q, want \"unknown\"", status)
	}
}
