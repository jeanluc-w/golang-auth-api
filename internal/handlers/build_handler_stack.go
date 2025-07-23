package handlers

import (
	"edibubble-api/internal/middleware"
	"net/http"

	"go.uber.org/zap"
)

func BuildHandlerStack(router http.Handler, logger *zap.Logger) http.Handler {
	stack := middleware.ResponseWriterMiddleware(
		middleware.RequestIDMiddleware(
			middleware.LoggerMiddleware(logger)(
				middleware.JSONMiddleware(
					middleware.ResponseHeadersMiddleware(
						middleware.RateLimitMiddleware(
							middleware.JWTMiddleware(
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
