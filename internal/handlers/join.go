package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"edibubble-api/config"
	"edibubble-api/internal/redis"
	"edibubble-api/internal/services"
	"edibubble-api/internal/utils"
)

type JoinRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Origin   string `json:"origin"`
}

type JoinResponse struct {
	Status       string `json:"status"`
	Message      string `json:"message"`
	Token        string `json:"token,omitempty"`
	ShowVerifyUI bool   `json:"show_verify_ui"`
}

func JoinHandler(cfg *config.Config, redisClient *redis.Client, authService *services.AuthService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = r.Referer()
		}
		var req JoinRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.Origin != "" {
			origin = req.Origin
		}
		if !utils.IsOriginAllowed(origin, cfg.AllowedOrigins) {
			http.Error(w, "Forbidden origin", http.StatusForbidden)
			return
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		email := strings.TrimSpace(strings.ToLower(req.Email))
		password := strings.TrimSpace(req.Password)

		if !utils.IsValidEmail(email) || len(password) < 8 {
			http.Error(w, "Invalid email or password", http.StatusBadRequest)
			return
		}

		exists, err := authService.UserExistsByEmail(email)
		if err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		if exists {
			http.Error(w, "Account already exists", http.StatusConflict)
			return
		}

		if redisClient.EmailJoinPending(email) {
			json.NewEncoder(w).Encode(JoinResponse{
				Status:       "pending_verification",
				Message:      "Check your email to verify your account.",
				ShowVerifyUI: true,
			})
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to process password", http.StatusInternalServerError)
			return
		}

		token := uuid.New().String()
		payload := map[string]string{
			"email":         email,
			"password_hash": string(hash),
		}
		err = redisClient.StoreJoinToken(token, payload, time.Minute*15)
		if err != nil {
			http.Error(w, "Failed to prepare verification", http.StatusInternalServerError)
			return
		}

		err = authService.SendVerificationEmail(email, token)
		if err != nil {
			http.Error(w, "Failed to send verification email", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(JoinResponse{
			Status:       "pending_verification",
			Message:      "Check your email to verify your account.",
			ShowVerifyUI: true,
		})
	}
}
