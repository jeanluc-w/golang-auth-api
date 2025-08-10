package entities

type ContextKey string

const (
	UserContextKey                    ContextKey = "user"
	RequestContextKey                 ContextKey = "request_id"
	StartTimeContextKey               ContextKey = "request_start_time"
	LoggerContextKey                  ContextKey = "logger"
	EmailFromDecodedTempJWTContextKey ContextKey = "email_from_temporary_jwt"
	JTIFromDecodedTempJWTContextKey   ContextKey = "id_from_temporary_jwt"
	ClientIPContextKey                ContextKey = "client_ip"
	UserAgentContextKey               ContextKey = "user_agent"
)
