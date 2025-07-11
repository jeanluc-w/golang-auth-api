package utils

import (
	"net/http"

	"go.uber.org/zap"
)

// LogInfo logs an info-level message with request and session info.
func Info(logger *zap.Logger, r *http.Request, message string, fields ...zap.Field) {
	logger.Info(message, buildFields(r, fields...)...)
}

// LogWarn logs a warning-level message with request and session info.
func Warn(logger *zap.Logger, r *http.Request, message string, fields ...zap.Field) {
	logger.Warn(message, buildFields(r, fields...)...)
}

// LogError logs an error-level message with request and session info.
func Error(logger *zap.Logger, r *http.Request, message string, fields ...zap.Field) {
	logger.Error(message, buildFields(r, fields...)...)
}

// buildFields constructs the common zap fields for logging.
func buildFields(r *http.Request, fields ...zap.Field) []zap.Field {
	sessionID := ""
	if v := r.Context().Value("session_id"); v != nil {
		if s, ok := v.(string); ok {
			sessionID = s
		}
	}
	requestID := ""
	if v := r.Context().Value("request_id"); v != nil {
		if s, ok := v.(string); ok {
			requestID = s
		}
	}

	baseFields := []zap.Field{
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("session_id", sessionID),
		zap.String("request_id", requestID),
		zap.String("user_agent", r.UserAgent()),
	}
	return append(baseFields, fields...)
}
