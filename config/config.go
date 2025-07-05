package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Port           string
	DatabaseURL    string
	RedisURL       string
	JWTSecret      string
	AllowedOrigins []string
}

func Load() *Config {
	_ = godotenv.Load()

	return &Config{
		Port:           get("PORT", "8080"),
		DatabaseURL:    must("DATABASE_URL"),
		RedisURL:       must("REDIS_URL"),
		JWTSecret:      must("JWT_SECRET"),
		AllowedOrigins: []string{"http://localhost:3000", "https://edibubble.app"}, // update
	}
}

func must(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("Missing required env var: %s", key)
	}
	return v
}

func get(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
