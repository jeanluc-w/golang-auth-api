package entities

type ContextKey string

const (
	UserContextKey                    ContextKey = "user"
	RequestContextKey                 ContextKey = "request_id"
	StartTimeContextKey               ContextKey = "request_start_time"
	LoggerContextKey                  ContextKey = "logger"
	EmailFromTempJWTContextKey        ContextKey = "email_from_temporary_jwt"
	JTIFromTempJWTContextKey          ContextKey = "id_from_temporary_jwt"
	ClientIPContextKey                ContextKey = "client_ip"
	UserAgentContextKey               ContextKey = "user_agent"
	SessionIDFromExpiredJWTContextKey ContextKey = "session_id_from_expired_jwt"
)
