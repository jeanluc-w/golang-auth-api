package entities

import "github.com/golang-jwt/jwt/v5"

// RoleJoiner marks a short-lived JWT issued after email verification but
// before the user has finished signup (chosen a username/password). It is
// never a persisted user role in the database.
const RoleJoiner = "joiner"

// JWTClaims are the custom claims carried by every access and temporary
// token this service issues. The session/token identifier lives in the
// standard `jti` claim (RegisteredClaims.ID) rather than a duplicate field,
// since it is already the canonical session key used in Redis and Postgres.
type JWTClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}
