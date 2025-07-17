package middleware

import (
	"edibubble-api/config"
	"net/http"
)

func TimeoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.TimeoutHandler(next, config.Loaded.RequestTimeout, `{"error":"request timeout"}`)
		next.ServeHTTP(w, r)
	})
}
