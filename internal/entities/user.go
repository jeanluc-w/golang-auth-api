package entities

// UserContext is the authenticated identity attached to a request's context
// once JWTMiddleware has verified the caller's access token.
type UserContext struct {
	ID        string
	Username  string
	SessionID string
	Role      string
}
