package handlers

import (
	"edibubble-api/config"
	"edibubble-api/internal/middleware"
	"net/http"

	"go.uber.org/zap"
)

func BuildHandlerStack(config *config.Config, router http.Handler, logger *zap.Logger) http.Handler {
	stack := middleware.JSONMiddleware(
		middleware.ResponseHeadersMiddleware(config)(
			middleware.JWTMiddleware(config)(
				middleware.RequestIDMiddleware(
					middleware.LoggerMiddleware(logger)(
						middleware.RateLimitMiddleware(config)(
							middleware.TimeoutMiddleware(config.RequestTimeout)(
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
