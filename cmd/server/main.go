package main

import (
	"log"
	"net/http"

	"edibubble-api/config"
	"edibubble-api/internal/handlers"
	"edibubble-api/internal/redis"
	"edibubble-api/internal/services"
)

func main() {
	cfg := config.Load()

	redisClient := redis.New(cfg)
	authService := services.NewAuthService(cfg)

	http.HandleFunc("/signup", handlers.JoinHandler(cfg, redisClient, authService))
	http.HandleFunc("/verify-email", handlers.VerifyEmailHandler(cfg, redisClient, authService))

	log.Printf("Server running on :%s", cfg.Port)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, nil))
}
