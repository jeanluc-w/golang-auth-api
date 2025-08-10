package utils

import (
	"context"
	"time"

	"edibubble-api/internal/entities"
)

func ClientIPFromCtx(ctx context.Context) string {
	return GetContextString(ctx, entities.ClientIPContextKey, "")
}

func UserAgentFromCtx(ctx context.Context) string {
	return GetContextString(ctx, entities.UserAgentContextKey, "")
}

func GetContextString(ctx context.Context, key entities.ContextKey, fallback string) string {
	if val, ok := ctx.Value(key).(string); ok {
		return val
	}
	return fallback
}

func GetContextTime(ctx context.Context, key entities.ContextKey) time.Time {
	if val, ok := ctx.Value(key).(time.Time); ok {
		return val
	}
	// Default to current time
	return time.Now()
}
