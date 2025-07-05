package services

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"edibubble-api/config"
)

type AuthService struct {
	cfg *config.Config
}

func NewAuthService(cfg *config.Config) *AuthService {
	return &AuthService{cfg: cfg}
}

func (a *AuthService) SendVerificationEmail(email, token string) error {
	// TODO: Connect to real SMTP service
	fmt.Printf("Simulated email: Visit https://edibubble.app/verify-email?token=%s\n", token)
	return nil
}

func (a *AuthService) UserExistsByEmail(email string) (bool, error) {
	// TODO: Query DB
	return false, nil
}

func (a *AuthService) CreateUser(email, hash string) (string, error) {
	// TODO: Insert into DB and return user ID
	return "new-user-id", nil
}

func (a *AuthService) GenerateJWT(userID string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	})
	return token.SignedString([]byte(a.cfg.JWTSecret))
}
