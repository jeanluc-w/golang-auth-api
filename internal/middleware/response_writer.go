package middleware

import (
	"edibubble-api/internal/models"
	"net/http"
)

func ResponseWriterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &models.ResponseWriter{ResponseWriter: w, Status: http.StatusOK}
		next.ServeHTTP(rw, r)
	})
}
