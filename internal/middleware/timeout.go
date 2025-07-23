package middleware

import (
	"edibubble-api/config"
	"net/http"
)

func TimeoutMiddleware(next http.Handler) http.Handler {
	return http.TimeoutHandler(next, config.Loaded.RequestTimeout, `{"error":"request timeout"}`)
}
