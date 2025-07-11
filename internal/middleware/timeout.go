package middleware

import (
	"net/http"
	"time"
)

func TimeoutMiddleware(duration time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.TimeoutHandler(next, duration, `{"error":"request timeout"}`)
	}
}
