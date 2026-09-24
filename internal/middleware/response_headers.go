package middleware

import (
	"auth-api/config"
	"auth-api/internal/utils"
	"net/http"
)

// ResponseHeadersMiddleware sets CORS and security headers on every response.
//
// CORS origins are configured via the ALLOWED_ORIGINS env var (comma-separated).
// In development with no origins configured, any origin is allowed for ease of
// local testing; in every other case an unlisted Origin simply gets no
// Access-Control-Allow-Origin header, which browsers treat as a same-origin-only
// (i.e. cross-origin blocked) response.
func ResponseHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		switch {
		case config.Loaded.Env == "development" && len(config.Loaded.AllowedOrigins) == 0:
			w.Header().Set("Access-Control-Allow-Origin", "*")
		case origin != "" && utils.IsOriginAllowed(origin, config.Loaded.AllowedOrigins):
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")

		// Preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none';")

		next.ServeHTTP(w, r)
	})
}
