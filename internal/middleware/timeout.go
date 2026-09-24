package middleware

import (
	"auth-api/config"
	"net/http"
)

// TimeoutMiddleware bounds request handling to config.Loaded.RequestTimeout,
// returning a JSON timeout error if it's exceeded.
func TimeoutMiddleware(next http.Handler) http.Handler {
	return http.TimeoutHandler(next, config.Loaded.RequestTimeout, `{"error":"request timeout"}`)
}
