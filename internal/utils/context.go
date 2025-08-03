package utils

import (
	"net/http"
	"time"

	"edibubble-api/internal/entities"
)

func GetContextString(r *http.Request, key entities.ContextKey, fallback string) string {
	if val, ok := r.Context().Value(key).(string); ok {
		return val
	}
	return fallback
}

func GetContextTime(r *http.Request, key entities.ContextKey) time.Time {
	if val, ok := r.Context().Value(key).(time.Time); ok {
		return val
	}
	// Default to current time
	return time.Now()
}
