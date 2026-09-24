package middleware

import (
	"net"
	"net/http"
	"strings"

	"auth-api/internal/entities"
	"auth-api/internal/utils"

	"github.com/getsentry/sentry-go"
	"github.com/ulule/limiter/v3"
	"go.uber.org/zap"
)

// clientIP extracts the request's client IP, preferring net.SplitHostPort
// over a raw strings.Split on ":" (which breaks on IPv6 addresses).
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return host
	}
	// Fallback for envs where RemoteAddr has no port.
	return strings.Split(r.RemoteAddr, ":")[0]
}

// checkRateLimit applies l's limit to key, writing the appropriate JSON
// error response and returning false if the limit is exceeded or the
// limiter store itself errors. Shared by RateLimitMiddleware (IP-keyed,
// applies to every request) and UserRateLimitMiddleware (user-keyed,
// applies only once a request is authenticated).
func checkRateLimit(w http.ResponseWriter, r *http.Request, l *limiter.Limiter, key string) bool {
	ctx := r.Context()

	res, err := l.Get(ctx, key)
	if err != nil {
		utils.LogError(ctx, "Rate limiter store error", zap.Error(err))
		utils.JSONError(w, utils.Errors.InternalServerError)
		return false
	}

	utils.LogDebug(ctx, "Rate limiting check",
		zap.String("rate_key", key),
		zap.Int64("limit", res.Limit),
		zap.Int64("remaining", res.Remaining),
		zap.Int64("reset", res.Reset),
	)

	if !res.Reached {
		return true
	}

	sentry.WithScope(func(scope *sentry.Scope) {
		scope.SetLevel(sentry.LevelWarning)
		scope.SetTag("rate_key", key)
		scope.SetExtra("limit", res.Limit)
		scope.SetExtra("remaining", res.Remaining)
		scope.SetExtra("reset", res.Reset)
	})
	sentry.CaptureMessage("Rate limit exceeded")

	utils.LogWarn(ctx, "Rate limit exceeded",
		zap.String("rate_key", key),
		zap.Int64("limit", res.Limit),
		zap.Int64("remaining", res.Remaining),
		zap.Int64("reset", res.Reset),
	)
	utils.JSONError(w, utils.Errors.TooManyAttempts)
	return false
}

// RateLimitMiddleware throttles every request by client IP, using a
// Redis-backed sliding window (config.Loaded.RateLimit). It runs before
// JWTMiddleware in BuildHandlerStack specifically so that requests with a
// missing/invalid/expired token are still throttled — an attacker hammering
// a protected route with garbage tokens doesn't get a free pass just
// because auth rejects them first. This is baseline, always-on abuse
// protection; see UserRateLimitMiddleware for the per-authenticated-user
// layer on top of it.
func RateLimitMiddleware(l *limiter.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !checkRateLimit(w, r, l, "ip:"+clientIP(r)) {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// UserRateLimitMiddleware applies a SEPARATE rate limit keyed by
// authenticated user ID, layered on top of (not instead of)
// RateLimitMiddleware's IP-based limiting. It must run AFTER JWTMiddleware
// in BuildHandlerStack, since that's what populates
// entities.UserContextKey. Requests with no authenticated user in context —
// open routes, temp-JWT ("joiner") routes, and the refresh-token route's
// expired-JWT-only context — pass through unaffected; they rely solely on
// RateLimitMiddleware's IP-based check.
//
// The point of this second layer: several users behind the same NAT/
// corporate IP no longer share a single rate-limit budget, and a single
// user rotating IPs can't use that to dodge their own per-account limit.
func UserRateLimitMiddleware(l *limiter.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, _ := r.Context().Value(entities.UserContextKey).(*entities.UserContext)
			if user == nil || user.ID == "" {
				next.ServeHTTP(w, r)
				return
			}
			if !checkRateLimit(w, r, l, "user:"+user.ID) {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
