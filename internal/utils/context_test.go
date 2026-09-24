package utils

import (
	"context"
	"testing"
	"time"

	"auth-api/internal/entities"
)

func TestGetContextString(t *testing.T) {
	ctx := context.WithValue(context.Background(), entities.RequestContextKey, "req-123")

	if got := GetContextString(ctx, entities.RequestContextKey, "fallback"); got != "req-123" {
		t.Errorf("got %q, want %q", got, "req-123")
	}
	if got := GetContextString(ctx, entities.ClientIPContextKey, "fallback"); got != "fallback" {
		t.Errorf("missing key: got %q, want fallback", got)
	}
}

func TestClientIPAndUserAgentFromCtx(t *testing.T) {
	ctx := context.WithValue(context.Background(), entities.ClientIPContextKey, "1.2.3.4")
	ctx = context.WithValue(ctx, entities.UserAgentContextKey, "test-agent/1.0")

	if got := ClientIPFromCtx(ctx); got != "1.2.3.4" {
		t.Errorf("ClientIPFromCtx = %q, want %q", got, "1.2.3.4")
	}
	if got := UserAgentFromCtx(ctx); got != "test-agent/1.0" {
		t.Errorf("UserAgentFromCtx = %q, want %q", got, "test-agent/1.0")
	}
	if got := ClientIPFromCtx(context.Background()); got != "" {
		t.Errorf("ClientIPFromCtx with no value = %q, want empty", got)
	}
}

func TestGetContextTime(t *testing.T) {
	now := time.Now()
	ctx := context.WithValue(context.Background(), entities.StartTimeContextKey, now)

	if got := GetContextTime(ctx, entities.StartTimeContextKey); !got.Equal(now) {
		t.Errorf("got %v, want %v", got, now)
	}
	// No value set: should default to "now" rather than the zero time, per
	// the documented fallback behavior.
	if got := GetContextTime(context.Background(), entities.StartTimeContextKey); time.Since(got) > time.Second {
		t.Errorf("expected fallback close to now, got %v", got)
	}
}
