package main

import (
	"log"
	"net/http"

	"edibubble-api/config"
	"edibubble-api/internal/handlers"
)

func main() {
	cfg := config.Load()

	http.HandleFunc("/signup", handlers.SignupHandler(cfg))
	http.HandleFunc("/verify", handlers.VerifyEmailHandler(cfg))
	http.HandleFunc("/signin", handlers.SigninHandler(cfg))

	log.Printf("Server starting on port %s...", cfg.Port)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, nil))
}
