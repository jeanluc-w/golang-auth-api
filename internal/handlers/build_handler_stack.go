package handlers

import (
	"edibubble-api/internal/middleware"
	"edibubble-api/internal/server"
	"net/http"
)

func BuildHandlerStack(router http.Handler, svcs *server.Services) http.Handler {
	stack := middleware.ResponseWriterMiddleware(
		middleware.RequestIDMiddleware(
			middleware.LoggerMiddleware(svcs.Logger)(
				middleware.JSONMiddleware(
					middleware.ResponseHeadersMiddleware(
						middleware.RateLimitMiddleware(svcs.Limiter)(
							middleware.JWTMiddleware(svcs.RedisClient)(
								middleware.TimeoutMiddleware(
									router,
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
