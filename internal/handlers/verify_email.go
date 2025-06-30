package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"edibubble-api/config"
	"edibubble-api/internal/redis"
	"edibubble-api/internal/services"
)

type VerifyEmailRequest struct {
	Token string `json:"token"`
}

type VerifyEmailResponse struct {
	Status  string `json:"status"` // "success"
	Token   string `json:"token"`
	Message string `json:"message"`
}

func VerifyEmailHandler(cfg *config.Config, redisClient *redis.Client, authService *services.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req VerifyEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		data, err := redisClient.ConsumeSignupToken(req.Token)
		if err != nil || len(data) == 0 {
			http.Error(w, "Invalid or expired token", http.StatusBadRequest)
			return
		}

		userID := uuid.New().String()
		email := data["email"]
		hash := data["password_hash"]

		id, err := authService.CreateUser(email, hash)
		if err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		jwt, err := authService.GenerateJWT(id)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(VerifyEmailResponse{
			Status:  "success",
			Token:   jwt,
			Message: "Account verified and created",
		})
	}
}
