package server

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/resend/resend-go/v2"
	"github.com/ulule/limiter/v3"
	"go.uber.org/zap"
)

type Services struct {
	DB           *pgxpool.Pool
	RedisClient  *redis.Client
	ResendClient *resend.Client
	Limiter      *limiter.Limiter
	Logger       *zap.Logger
}

func NewServices(
	db *pgxpool.Pool,
	redis *redis.Client,
	resend *resend.Client,
	lim *limiter.Limiter,
	logger *zap.Logger,
) *Services {
	return &Services{
		DB: db, RedisClient: redis, ResendClient: resend, Limiter: lim, Logger: logger,
	}
}

// Start runs the HTTP server with graceful shutdown support.
func Start(server *http.Server, shutdownTimeout time.Duration) {
	// Start server in a goroutine
	go func() {
		log.Printf("Server running on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	gracefulShutdown(server, shutdownTimeout)
}

// gracefulShutdown handles SIGINT/SIGTERM and shuts down the server cleanly.
func gracefulShutdown(server *http.Server, timeout time.Duration) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server gracefully stopped.")
}
