package middleware

import (
	"edibubble-api/internal/utils"
	"net/http"
	"strings"
)

// Ensures only application/json is used for POST/PATCH/PUT requests, and sets response content type.
func JSONMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
			if contentType := r.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
				utils.JSONError(w, http.StatusUnsupportedMediaType, "Expected Content-Type application/json")
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}
