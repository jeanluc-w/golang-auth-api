package handlers

import (
	"edibubble-api/internal/middleware"
	"net/http"

	"go.uber.org/zap"
)

func BuildHandlerStack(router http.Handler, logger *zap.Logger) http.Handler {
	stack := middleware.JSONMiddleware(
		middleware.ResponseHeadersMiddleware(
			middleware.JWTMiddleware(
				middleware.RequestIDMiddleware(
					middleware.LoggerMiddleware(logger)(
						middleware.RateLimitMiddleware(
							middleware.TimeoutMiddleware(
								router,
							),
						),
					),
				),
			),
		),
	)
	return stack
}
