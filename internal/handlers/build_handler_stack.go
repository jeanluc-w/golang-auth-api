package handlers

import (
	"auth-api/internal/middleware"
	"auth-api/internal/server"
	"net/http"
)

// BuildHandlerStack wraps router with the full middleware chain.
//
// Rate limiting is layered in two passes around JWTMiddleware:
//  1. RateLimitMiddleware (IP-keyed) runs BEFORE auth, so every request —
//     including ones with a missing/invalid/expired token — is throttled.
//     An attacker hammering a protected route with garbage tokens doesn't
//     get a free pass just because auth rejects them first.
//  2. UserRateLimitMiddleware (user-ID-keyed) runs AFTER auth, once
//     JWTMiddleware has populated the authenticated user in context, giving
//     each account its own budget independent of shared-IP effects.
//
// See both middlewares' doc comments in internal/middleware/rate_limit.go
// for the full rationale.
func BuildHandlerStack(router http.Handler, svcs *server.Services) http.Handler {
	stack := middleware.ResponseWriterMiddleware(
		middleware.RequestIDMiddleware(
			middleware.LoggerMiddleware(svcs.Logger)(
				middleware.JSONMiddleware(
					middleware.ResponseHeadersMiddleware(
						middleware.RateLimitMiddleware(svcs.Limiter)(
							middleware.JWTMiddleware(svcs.RedisClient)(
								middleware.UserRateLimitMiddleware(svcs.Limiter)(
									middleware.TimeoutMiddleware(
										router,
									),
								),
							),
						),
					),
				),
			),
		),
	)
	return stack
}
