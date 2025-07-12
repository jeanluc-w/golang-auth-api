package utils

import (
	"net/http"
	"time"

	"edibubble-api/internal/models"
)

func GetContextString(r *http.Request, key models.ContextKey, fallback string) string {
	if val, ok := r.Context().Value(key).(string); ok {
		return val
	}
	return fallback
}

func GetContextTime(r *http.Request, key models.ContextKey) time.Time {
	if val, ok := r.Context().Value(key).(time.Time); ok {
		return val
	}
	// Default to current time
	return time.Now()
}
