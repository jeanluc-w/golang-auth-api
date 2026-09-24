// Package integration runs the auth flows (signup completion, login,
// refresh, logout) against real Postgres and Redis containers via
// testcontainers-go, exercising the actual SQL queries, triggers, and
// Redis TTL behavior rather than mocks.
//
// It lives in its own nested Go module (see go.mod) specifically so that
// testcontainers-go's heavy dependency tree (Docker client, OpenTelemetry,
// etc.) never pollutes the main module's go.mod/go.sum for people who just
// want to import or read the library itself. It uses a `replace` directive
// to point back at the local checkout of the root module.
//
// Requires a working Docker (or Podman via testcontainers' compatibility
// mode) daemon. Run with: go test ./...  (from this directory)
package integration

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"auth-api/config"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/ulule/limiter/v3"
)

var (
	testDB    *pgxpool.Pool
	testRedis *redis.Client
)

const migrationsDir = "../../db/migrations"

func TestMain(m *testing.M) {
	ctx := context.Background()

	pgContainer, err := tcpostgres.Run(ctx, "postgres:16",
		tcpostgres.WithDatabase("auth_test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		fmt.Println("failed to start postgres container:", err)
		os.Exit(1)
	}
	defer pgContainer.Terminate(ctx)

	redisContainer, err := tcredis.Run(ctx, "redis:7")
	if err != nil {
		fmt.Println("failed to start redis container:", err)
		os.Exit(1)
	}
	defer redisContainer.Terminate(ctx)

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Println("failed to get postgres connection string:", err)
		os.Exit(1)
	}
	if err := applyMigrations(ctx, dsn); err != nil {
		fmt.Println("failed to apply migrations:", err)
		os.Exit(1)
	}

	testDB, err = pgxpool.New(ctx, dsn)
	if err != nil {
		fmt.Println("failed to connect pgxpool:", err)
		os.Exit(1)
	}
	defer testDB.Close()

	redisAddr, err := redisContainer.Endpoint(ctx, "")
	if err != nil {
		fmt.Println("failed to get redis endpoint:", err)
		os.Exit(1)
	}
	testRedis = redis.NewClient(&redis.Options{Addr: redisAddr})
	defer testRedis.Close()

	configureTestConfig()

	os.Exit(m.Run())
}

// applyMigrations executes every *.up.sql file in db/migrations, in
// filename order, against dsn. It intentionally avoids pulling in a
// migration library — this only ever needs to build a fresh schema, never
// migrate a live one.
func applyMigrations(ctx context.Context, dsn string) error {
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".up.sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	for _, f := range files {
		sqlBytes, err := os.ReadFile(filepath.Join(migrationsDir, f))
		if err != nil {
			return fmt.Errorf("reading %s: %w", f, err)
		}
		if _, err := conn.Exec(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("applying %s: %w", f, err)
		}
	}
	return nil
}

// configureTestConfig populates config.Loaded with values equivalent to
// what config.Load() would build from the environment, but with a freshly
// generated JWT keypair and tight TTLs so lockout/expiry scenarios don't
// require the test suite to sleep for long.
func configureTestConfig() {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	config.Loaded = &config.Config{
		Env:                    "test",
		PasswordPeppersRaw:     "test-active:MDEyMzQ1Njc4OWFiY2RlZg==,test-legacy:ZmVkY2JhOTg3NjU0MzIxMA==",
		ActivePepperID:         "test-active",
		EmailFromAddress:       "auth <no-reply@mail.auth.com>",
		RateLimit:              limiter.Rate{Period: time.Second, Limit: 1000},
		RequestTimeout:         10 * time.Second,
		OTP_TTL:                10 * time.Minute,
		AccessTTL:              2 * time.Second,
		RefreshTTL:             time.Hour,
		TemporaryTokenTTL:      time.Minute,
		LoginMaxFailedAttempts: 3,
		LoginLockDuration:      2 * time.Second,
		JWTPrivateKey:          priv,
		JWTPublicKey:           pub,
		JWTAlgorithm:           jwt.SigningMethodEdDSA,
	}
}
