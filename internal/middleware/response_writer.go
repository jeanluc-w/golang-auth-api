package middleware

import (
	"auth-api/internal/entities"
	"net/http"
)

func ResponseWriterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &entities.ResponseWriter{ResponseWriter: w, Status: http.StatusOK}
		next.ServeHTTP(rw, r)
	})
}
