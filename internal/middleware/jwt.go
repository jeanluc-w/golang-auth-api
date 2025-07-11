package middleware

import "net/http"

func JWTMiddleware(next http.Handler) http.Handler {
	// TODO: add auth logic of verifying JWT, decoding it, verify session exists in db and is valid,
	// pass session id to the request context, and then adding user info to the request context.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}
