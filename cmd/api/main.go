package main

import (
	"context"
	"edibubble/internal/data"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/joho/godotenv"
	"google.golang.org/api/option"
)

const version = "1.0.0"

// A config struct to hold all the configuration settings for our application.
// Configuration settings are the network port that we want the server
// to listen on, the name of the current environment for the
// application (dev or prod), and the database connection.
// The values are read in from the command line.
type config struct {
	port int
	env  string
	cors struct {
		trustedOrigins []string
	}
}

// An application struct to hold the dependencies for our HTTP handlers, helpers,
// and middleware.
type application struct {
	config config
	logger *slog.Logger
	models data.Models
}

func main() {
	// Declare an instance of the config struct and single error object.
	var cfg config
	var err error

	// Initialize the logger.
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Read the environment variables into the config.
	// Shut it down if it isn't properly set up in certain aspects.
	err = godotenv.Load()
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	// Set basic server information (Port and environment)
	cfg.port, err = strconv.Atoi(getEnv("SERVER_PORT", "4000"))
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	cfg.env = getEnv("ENVIRONMENT", "dev")

	// Get the list of allowed origins
	cfg.cors.trustedOrigins = strings.Fields(getEnv("TRUSTED_CORS_ORIGINS", ""))
	logger.Info(fmt.Sprintf("Allowing cross-origins: %s", cfg.cors))

	// Start Firestore connection
	ctx := context.Background()
	opt := option.WithCredentialsFile("secrets/serviceAccountKey.json")
	client, err := firestore.NewClient(ctx, getEnv("FIRESTORE_ID", ""), opt)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	defer client.Close()

	logger.Info("database connection pool established")

	// Initialize the application struct, containing the config struct and
	// the logger.
	app := &application{
		config: cfg,
		logger: logger,
		models: data.NewModels(client),
	}

	// Declare the HTTP server
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.port),
		Handler:      app.routes(),
		IdleTimeout:  time.Minute,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		ErrorLog:     slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	// Start the HTTP server.
	logger.Info("starting server", "addr", srv.Addr, "env", cfg.env)
	err = srv.ListenAndServe()
	logger.Error(err.Error())
	os.Exit(1)
}
