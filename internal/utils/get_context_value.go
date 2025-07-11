package utils

import "net/http"

func GetContextValue(r *http.Request, key string, defaultValue string) string {
	val := r.Context().Value(key)
	if s, ok := val.(string); ok {
		return s
	}
	return defaultValue
}
