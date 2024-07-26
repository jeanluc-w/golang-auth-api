package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
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
	db   struct {
		dsn string
	}
}

// An application struct to hold the dependencies for our HTTP handlers, helpers,
// and middleware.
type application struct {
	config config
	logger *slog.Logger
}

func main() {
	// Declare an instance of the config struct and single error object.
	var cfg config
	var err error
	// Initialize the logger.
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	// Read the value of the port and env command-line flags into the config struct. We
	// default to using the port number 4000, the environment "development", and
	// the development DSN if no corresponding flags are provided.
	err = godotenv.Load()
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	cfg.port, err = strconv.Atoi(getEnv("SERVER_PORT", "4000"))
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	cfg.env = getEnv("ENVIRONMENT", "dev")
	cfg.db.dsn = os.Getenv("POSTGRES_CONNECTION_STRING")
	if len(cfg.db.dsn) == 0 {
		logger.Error("missing database connection string")
		os.Exit(1)
	}
	// Initialize the DB connection pool and defer its closing to just before main() exits
	dbpool, err := openDB(cfg)
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	defer dbpool.Close()
	// Initialize the application struct, containing the config struct and
	// the logger.
	app := &application{
		config: cfg,
		logger: logger,
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

// Open the DB connection pool
func openDB(config config) (*pgxpool.Pool, error) {
	// Create the connection pool
	pool, err := pgxpool.New(context.Background(), config.db.dsn)
	if err != nil {
		return nil, err
	}

	return pool, nil
}
