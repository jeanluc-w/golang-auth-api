package utils

import (
	"context"
	"time"

	"edibubble-api/internal/entities"
)

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
