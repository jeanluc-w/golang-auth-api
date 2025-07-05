package handlers

import (
	"edibubble-api/config"
	"edibubble-api/internal/redis"
	"edibubble-api/internal/services"
	"edibubble-api/internal/utils"
	"net/http"
	"time"
)

func JoinHandler(cfg *config.Config, redisClient *redis.Client, authService *services.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		email := r.FormValue("email")
		if email == "" && !utils.IsValidEmail(email) {
			http.Error(w, "Valid email is required", http.StatusBadRequest)
			return
		}

		if redisClient.EmailSignupPending(email) {
			http.Error(w, "Signup already pending for this email", http.StatusConflict)
			return
		}

		token, err := authService.GenerateSignupToken(email)
		if err != nil {
			http.Error(w, "Failed to generate signup token", http.StatusInternalServerError)
			return
		}

		data := map[string]string{"email": email}
		err = redisClient.StoreSignupToken(token, data, time.Hour)
		if err != nil {
			http.Error(w, "Failed to store signup token", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Signup token generated successfully"))
	}
}
