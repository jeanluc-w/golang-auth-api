package utils

import (
	"edibubble-api/config"
	"edibubble-api/internal/middleware"
	"net/http"

	"go.uber.org/zap"
)

func buildHandlerStack(config config.Config, router http.Handler, logger *zap.Logger) http.Handler {
	return middleware.JSONMiddleware(
		middleware.CORSMiddleware(
			middleware.SecurityHeadersMiddleware(
				middleware.RequestIDMiddleware(
					middleware.SentryRecoveryMiddleware(logger)(
						middleware.LoggerMiddleware(logger)(
							middleware.RateLimitMiddleware(config)(
								router,
							),
						),
					),
				),
			),
		),
	)
}
