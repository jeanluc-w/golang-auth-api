package utils

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth-api/internal/entities"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// observedLoggerContext builds a context carrying a DynamicLogger backed by
// an observer core, so log calls can be asserted against directly.
func observedLoggerContext(extraOpts ...zap.Option) (context.Context, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core, extraOpts...)
	ctx := context.WithValue(context.Background(), entities.LoggerContextKey, &DynamicLogger{
		Base:      logger,
		StartTime: time.Now(),
	})
	return ctx, logs
}

func TestGetLogger_NoLoggerInContext_ReturnsUsableNoop(t *testing.T) {
	logger := getLogger(context.Background())
	if logger == nil {
		t.Fatal("expected a non-nil no-op logger")
	}
	// Must not panic when used.
	logger.Info("this should be discarded silently")
}

func TestGetLogger_AttachesDuration(t *testing.T) {
	ctx, logs := observedLoggerContext()
	LogInfo(ctx, "hello")

	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}
	found := false
	for _, f := range entries[0].Context {
		if f.Key == "duration" {
			found = true
		}
	}
	if !found {
		t.Error("expected the logged entry to carry a 'duration' field from DynamicLogger.withDuration")
	}
}

func TestLogLevelFunctions(t *testing.T) {
	cases := []struct {
		name  string
		log   func(ctx context.Context, msg string, fields ...zap.Field)
		level zapcore.Level
	}{
		{"LogInfo", LogInfo, zapcore.InfoLevel},
		{"LogWarn", LogWarn, zapcore.WarnLevel},
		{"LogError", LogError, zapcore.ErrorLevel},
		{"LogDebug", LogDebug, zapcore.DebugLevel},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, logs := observedLoggerContext()
			c.log(ctx, "test message", zap.String("k", "v"))

			entries := logs.All()
			if len(entries) != 1 {
				t.Fatalf("got %d log entries, want 1", len(entries))
			}
			if entries[0].Level != c.level {
				t.Errorf("level = %v, want %v", entries[0].Level, c.level)
			}
			if entries[0].Message != "test message" {
				t.Errorf("message = %q, want %q", entries[0].Message, "test message")
			}
		})
	}
}

func TestLogPanic_LogsAtPanicLevelAndPanics(t *testing.T) {
	ctx, logs := observedLoggerContext()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected LogPanic to panic")
		}
		entries := logs.All()
		if len(entries) != 1 {
			t.Fatalf("got %d log entries, want 1", len(entries))
		}
		if entries[0].Level != zapcore.PanicLevel {
			t.Errorf("level = %v, want PanicLevel", entries[0].Level)
		}
	}()

	LogPanic(ctx, "panic message")
	t.Fatal("unreachable: LogPanic should have panicked")
}

// TestLogFatal_LogsAtFatalLevel is the regression test for a bug where
// LogFatal called logger.Info(...) instead of logger.Fatal(...) — meaning a
// call meant to be fatal silently logged at info level and execution
// continued. zap.WithFatalHook(zapcore.WriteThenPanic) makes FatalLevel
// calls panic instead of calling os.Exit, so this can be asserted in-process
// without a subprocess.
func TestLogFatal_LogsAtFatalLevel(t *testing.T) {
	ctx, logs := observedLoggerContext(zap.WithFatalHook(zapcore.WriteThenPanic))

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected LogFatal to panic (via WriteThenPanic), meaning it never actually logged at Fatal level")
		}
		entries := logs.All()
		if len(entries) != 1 {
			t.Fatalf("got %d log entries, want 1", len(entries))
		}
		if entries[0].Level != zapcore.FatalLevel {
			t.Errorf("level = %v, want FatalLevel", entries[0].Level)
		}
	}()

	LogFatal(ctx, "fatal message")
	t.Fatal("unreachable: LogFatal should have panicked via the fatal hook")
}

// SendSentryLog guards setting its "duration_ms" tag behind
// !startTime.IsZero(), but GetContextTime (which it calls to get startTime)
// falls back to time.Now() rather than the zero Time when the context key
// is absent — so that guard can never actually be false through this call
// path, whether or not StartTimeContextKey was set. Both cases below
// therefore take the same "tag gets set" branch; this only asserts neither
// panics (SendSentryLog is safe to call before Sentry has been Init'd —
// sentry-go treats that as a documented no-op rather than an error).
func TestSendSentryLog_NoStartTimeInContext_DoesNotPanic(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	SendSentryLog(req, context.DeadlineExceeded)
}

func TestSendSentryLog_WithStartTimeInContext_DoesNotPanic(t *testing.T) {
	ctx := context.WithValue(context.Background(), entities.StartTimeContextKey, time.Now().Add(-time.Second))
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	SendSentryLog(req, context.DeadlineExceeded)
}
