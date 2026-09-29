package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/getsentry/sentry-go"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/resend/resend-go/v2"
	"github.com/ulule/limiter/v3"
	redisstore "github.com/ulule/limiter/v3/drivers/store/redis"
	"go.uber.org/zap"

	"auth-api/config"
	"auth-api/internal/auth"
	"auth-api/internal/handlers"
	"auth-api/internal/server"
)

func main() {
	// Load ENV variables
	config.Load()

	// Init Sentry
	config.InitSentry(config.Loaded.SentryDSN, config.Loaded.SentrySampleRate)
	defer sentry.Flush(config.Loaded.SentryFlushTimeout)

	// Init and ping the PostgreSQL connection pool
	pgPool, err := pgxpool.New(context.Background(), config.Loaded.DSN)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	if err := pgPool.Ping(context.Background()); err != nil {
		log.Fatalf("PostgreSQL ping failed: %v", err)
	}

	// Init and ping the Redis Client
	redisClient := redis.NewClient(&redis.Options{
		Addr:        config.Loaded.RedisAddress,
		DB:          0,
		DialTimeout: 5 * time.Second,
	})
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	// Init Resend Email Client
	resendClient := resend.NewClient(config.Loaded.ResendAPIKey)

	// Init Rate Limiter service
	store, err := redisstore.NewStoreWithOptions(redisClient, limiter.StoreOptions{
		Prefix:   "rl",
		MaxRetry: 1,
	})
	if err != nil {
		log.Fatalf("failed to create rate limiter store: %v", err)
	}
	limiterInstance := limiter.New(store, config.Loaded.RateLimit)

	// Init Zap logger
	logger := config.InitLogger(config.Loaded.Env)
	defer logger.Sync()

	// SSO providers are optional: a missing client ID or an unreachable
	// JWKS endpoint at startup disables just that provider (nil Keyfunc,
	// checked by the SSO handlers) rather than failing the whole server —
	// see server.Services' doc comment.
	googleJWKS := newProviderKeyfuncOrNil(config.Loaded.GoogleClientID, auth.GoogleJWKSURL, logger)
	appleJWKS := newProviderKeyfuncOrNil(config.Loaded.AppleClientID, auth.AppleJWKSURL, logger)

	// Passkeys are optional the same way: a missing WEBAUTHN_RP_ID disables
	// just that feature rather than failing the whole server.
	webAuthn := newWebAuthnOrNil(logger)

	// Establish 3rd Party services so handlers/services can use them
	services := server.NewServices(pgPool, redisClient, resendClient, limiterInstance, logger, googleJWKS, appleJWKS, webAuthn)

	// Build the full application handler: routes + middleware stack
	handler := handlers.NewHandler(services)

	// Create server
	srv := &http.Server{
		Addr:         ":" + config.Loaded.Port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start with graceful shutdown
	server.Start(srv, 15*time.Second)
}

// newProviderKeyfuncOrNil builds a keyfunc.Keyfunc for an SSO provider's
// JWKS, or returns nil if clientID is unset (provider not configured) or
// the initial fetch fails (logged, not fatal — see the call site's comment).
func newProviderKeyfuncOrNil(clientID, jwksURL string, logger *zap.Logger) keyfunc.Keyfunc {
	if clientID == "" {
		return nil
	}
	kf, err := auth.NewProviderKeyfunc(context.Background(), jwksURL)
	if err != nil {
		logger.Error("Failed to fetch JWKS for configured SSO provider; that provider will be unavailable", zap.String("jwks_url", jwksURL), zap.Error(err))
		return nil
	}
	return kf
}

// newWebAuthnOrNil builds the Relying Party WebAuthn instance, or returns
// nil if WEBAUTHN_RP_ID is unset (passkeys not configured) or the config
// is otherwise invalid (logged, not fatal — see the call site's comment).
func newWebAuthnOrNil(logger *zap.Logger) *webauthn.WebAuthn {
	if config.Loaded.WebAuthnRPID == "" {
		return nil
	}
	w, err := webauthn.New(&webauthn.Config{
		RPID:          config.Loaded.WebAuthnRPID,
		RPDisplayName: config.Loaded.WebAuthnRPDisplayName,
		RPOrigins:     config.Loaded.WebAuthnRPOrigins,
	})
	if err != nil {
		logger.Error("Failed to construct WebAuthn Relying Party; passkeys will be unavailable", zap.Error(err))
		return nil
	}
	return w
}
