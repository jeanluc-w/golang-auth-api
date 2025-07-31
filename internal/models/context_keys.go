package models

type ContextKey string

const (
	UserContextKey             ContextKey = "user"
	RequestContextKey          ContextKey = "request_id"
	StartTimeContextKey        ContextKey = "request_start_time"
	LoggerContextKey           ContextKey = "logger"
	EmailFromDecodedTempJWTKey ContextKey = "email_from_temporary_jwt"
)
