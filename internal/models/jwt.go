package models

import "github.com/golang-jwt/jwt/v5"

type JWTClaims struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	jwt.RegisteredClaims
}
