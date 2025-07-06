package middleware

import "net/http"

func JWTMiddleware(next http.Handler) http.Handler {
	// TODO: add auth logic later
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}
