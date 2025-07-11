package handlers

import (
	"edibubble-api/config"
	"edibubble-api/internal/middleware"
	"net/http"

	"go.uber.org/zap"
)

func buildHandlerStack(config config.Config, router http.Handler, logger *zap.Logger) http.Handler {
	stack := middleware.JSONMiddleware(
		middleware.ResponseHeadersMiddleware(
			middleware.JWTMiddleware(
				middleware.RequestIDMiddleware(
					middleware.LoggerMiddleware(logger)(
						middleware.RateLimitMiddleware(config)(
							router,
						),
					),
				),
			),
		),
	)
	return stack
}
