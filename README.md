# auth-api

A self-contained, Postgres + Redis backed authentication API in Go: email/password
signup and login, JWT access tokens, opaque rotating refresh tokens, session
revocation, failed-login lockout, and a fully generated type-safe DB layer
(sqlc). It started as the auth service for a different personal project;
that project changed direction, so this repo now exists as a clean,
reviewable, working reference implementation for people who want to see (or
reuse) a reasonably complete Go auth system.

It is not a drop-in package you `go get` — it's a small service you fork,
read, and adapt. Read the [Not implemented](#not-implemented) section before
using it for anything real.

## Features

- **Email/password auth** — signup via a 6-digit email verification code,
  then username/password; login; logout; refresh-token rotation.
- **Argon2id password hashing** with a per-deployment "pepper" (a
  secret-in-config, not-in-database value mixed into every hash) and support
  for rotating peppers without invalidating existing passwords.
- **JWT access tokens** (Ed25519-signed) + **opaque, rotating refresh
  tokens**, with reuse detection: replaying an already-rotated refresh token
  revokes the whole session, not just that request.
- **Failed-login lockout** per account, backed by columns already in the
  `auth_identities` table (`failed_attempts`, `locked_at`).
- **Session tracking in Postgres** (`sessions` table) in addition to Redis,
  so revocation survives a Redis flush and sessions are independently
  auditable.
- **Structured logging** (zap) with request IDs, and **Sentry** error/panic
  reporting wired into the middleware stack.
- **Rate limiting**, layered: a Redis-backed, IP-keyed limit applies to
  every request (including auth failures, so bad-token spam against
  protected routes is still throttled), plus a second limit keyed by
  authenticated user ID once a request passes JWT auth, so accounts don't
  share a budget just because they're behind the same IP. **CORS** with an
  explicit origin allowlist, and the standard security response headers
  (CSP, HSTS, X-Frame-Options, etc.).
- **sqlc-generated DB layer** — every query is plain SQL in `db/queries/`,
  compiled into type-safe Go in `internal/db/postgres/`.
- Unit tests for the security-critical packages (`internal/auth`,
  `internal/utils`, `internal/middleware`) with no external dependencies,
  plus a Docker-gated integration suite that runs the full signup → login →
  refresh → logout lifecycle against real Postgres and Redis containers.

## Architecture

```
cmd/main.go            wiring: config, DB/Redis/Sentry clients, routes, server start
config/                env parsing, JWT key loading, logger/Sentry init
internal/auth/          password hashing, JWT issuing/parsing, session helpers (pure-ish, few external deps)
internal/services/      business logic: one file per use case, orchestrates auth+db+redis
internal/handlers/      HTTP layer: decode request -> call service -> encode response
internal/middleware/    request ID, logging, CORS/security headers, rate limit, JWT auth, timeout
internal/db/postgres/   sqlc-generated queries + a couple of hand-written transactional helpers
internal/entities/      shared types: JWT claims, context keys, request-scoped user
internal/utils/         JSON I/O, validation, structured error codes, logging helpers
internal/emailer/       Resend email client + HTML template rendering
db/migrations/          schema (golang-migrate compatible .up.sql/.down.sql pairs)
db/queries/             hand-written SQL, source of truth for sqlc codegen
test/integration/       Docker-gated integration tests (separate Go module — see below)
```

Request flow: `main.go` calls `handlers.NewHandler`, which registers routes
and wraps them with `handlers.BuildHandlerStack` (response writer wrapper →
request ID → logging → JSON content-type enforcement → security
headers/CORS → IP rate limit → JWT auth → per-user rate limit → timeout →
router). `NewHandler` is also what the integration test suite calls, so
routing can never silently drift from what's actually deployed. Handlers
decode the request, call a service function, and translate the result to
JSON. Services own all business logic and are the layer to read first to
understand any given flow — they're not thin passthroughs to the DB.

## API

| Method | Path                               | Auth                  | Purpose |
|--------|-------------------------------------|------------------------|---------|
| GET    | `/v1/healthcheck`                   | none                   | Liveness check |
| POST   | `/auth/v1/start-email-verification` | none                   | Step 1 of signup: email a 6-digit code |
| POST   | `/auth/v1/verify-email`             | none                   | Step 2 of signup: verify the code, get a short-lived "joiner" JWT |
| POST   | `/auth/v1/complete-email-join`      | joiner JWT             | Step 3 of signup: set username/password, get access+refresh tokens |
| POST   | `/auth/v1/login`                    | none                   | Email/password login |
| POST   | `/auth/v1/logout`                   | access JWT             | Revoke the current session |
| POST   | `/auth/v1/refresh-token`            | expired-or-valid access JWT + refresh token in body | Rotate access+refresh tokens |

All error responses are `{"error": "<code>", "message": "<human text>"}`
with an appropriate HTTP status; see `internal/utils/error_codes.go` for the
full registry.

Known quirk: a request to a real path with the wrong HTTP method (e.g.
`POST /v1/healthcheck`, which is GET-only) currently returns **404**, not
405 — `router.MethodNotAllowed` is wired to the same handler as
`router.NotFound`, and that handler's status is `RouteNotFound`'s 404. This
is locked in by a test (`TestHTTP_MethodNotAllowed`) documenting the actual
behavior rather than silently "fixed," since changing response semantics is
a product decision, not a bug fix.

## Getting started

### 1. Start Postgres + Redis and run migrations

```bash
docker compose up -d redis postgres
docker compose run --rm migrate-up
```

### 2. Generate a JWT signing key (Ed25519)

```bash
mkdir -p secrets
openssl genpkey -algorithm ed25519 -outform PEM -out ./secrets/jwt_private_key.pem
openssl pkey -in ./secrets/jwt_private_key.pem -pubout -out ./secrets/jwt_public_key.pem
```

### 3. Configure environment

```bash
cp .copy.env .env
```

Then fill in `SENTRY_DSN`, `RESEND_API_KEY`, and `PASSWORD_PEPPERS` (each
pepper is 16+ random bytes, base64-encoded — `openssl rand -base64 16`).
See [Configuration](#configuration) below for what every variable does.

### 4. Run it

```bash
go run ./cmd/main.go
```

## Configuration

All configuration is environment variables (see `config/config.go` for the
authoritative list; `.copy.env` has a template with comments).

| Variable | Required | Default | Notes |
|---|---|---|---|
| `DATABASE_URL` | yes | — | Postgres connection string |
| `REDIS_ADDR` | yes | — | `host:port` |
| `JWT_PRIVATE_KEY_FILE` / `JWT_PUBLIC_KEY_FILE` | yes | — | PEM-encoded Ed25519 keypair |
| `JWT_PRIVATE_KEY_PASSPHRASE` | only if the private key is an encrypted PKCS8 block | — | |
| `PASSWORD_PEPPERS` | yes | — | `id:base64,id:base64,...` — see [Password peppers](#password-peppers) |
| `ACTIVE_PEPPER_ID` | yes | — | which id in `PASSWORD_PEPPERS` new hashes use |
| `SENTRY_DSN` | yes | — | set to any placeholder value to run without real error reporting |
| `RESEND_API_KEY` | yes | — | used to send verification-code emails |
| `EMAIL_FROM_ADDRESS` | no | `auth <no-reply@mail.auth.com>` | |
| `ALLOWED_ORIGINS` | no | empty | comma-separated CORS allowlist; empty + `ENV=development` allows any origin |
| `ENV` | no | `development` | `development` gets verbose logs + permissive CORS |
| `PORT` | no | `8080` | |
| `REQUEST_TIMEOUT_SECONDS` | no | `10` | per-request timeout |
| `REQUEST_RATE_LIMIT` | no | `10` | requests/second per user-or-IP |
| `LOGIN_MAX_FAILED_ATTEMPTS` | no | `5` | failed logins before lockout |
| `LOGIN_LOCK_DURATION_MINUTES` | no | `15` | how long a lockout lasts |
| `SENTRY_SAMPLE_RATE` | no | `1.0` | |

### Password peppers

A "pepper" is a secret value — held in config/a secret manager, never in the
database — mixed into every password hash. Unlike a per-user salt (which is
stored alongside the hash and only protects against rainbow tables), a
pepper means a stolen database dump alone is insufficient to brute-force
passwords offline; the attacker also needs the pepper.

`PASSWORD_PEPPERS` supports multiple peppers by id specifically so you can
rotate one without invalidating every existing password: add a new pepper,
point `ACTIVE_PEPPER_ID` at it, and keep the old one in the list. Existing
hashes keep verifying against their original (now-inactive) pepper, and are
transparently rehashed under the new active pepper the next time that user
logs in (see `auth.ShouldRehashActive`, called from `services.Login`). Once
you're confident no more logins will arrive using an old pepper (or you've
decided to force a re-auth instead), remove it from the list.

## Security notes

Written for someone reviewing this as a reference, not just using it — the
*why* matters more than the *what* here.

- **Refresh token reuse detection**: refresh tokens rotate on every use, and
  a stored hash (not the token itself) is what's persisted. If a refresh
  token is presented that doesn't match the current hash for its session,
  the entire session is revoked immediately rather than just rejecting that
  one request — a mismatch means either replay of an already-rotated token,
  or someone else has a copy of it, and in both cases the safest response is
  to kill the session. See `services.RefreshToken`.
- **Login timing/enumeration**: every login rejection *before* password
  verification (unknown email, deleted account, locked account) returns the
  same `invalid_credentials` error and runs a dummy password hash
  (`auth.VerifyDummyPassword`) so an unknown-email response costs roughly
  the same CPU time as a wrong-password response. Account status
  (banned/disabled) is only revealed *after* a correct password, since only
  someone who already knows the password gains anything from that
  information. See `services.Login`.
- **Lockout is checked before password verification**, not after — once
  locked, further guesses don't matter until the lock window passes, so
  there's no reason to pay the argon2 cost (and doing so would let an
  attacker distinguish "locked" from "wrong password" by response time).
- **JWT verification** rejects tokens signed with any algorithm other than
  the server's own (`internal/auth/jwt.go`'s `keyFunc`), which defends
  against algorithm-confusion attacks; issuer, audience, and expiry are all
  independently checked.
- **The refresh-token endpoint intentionally accepts an expired access
  token** — its only purpose there is to identify which session a refresh
  request belongs to (`auth.VerifyAndParseExpiredJWT`). It is never
  sufficient authentication by itself; the accompanying refresh token,
  checked against its stored hash, is what actually authenticates the
  request.
- **Redis failures fail closed** on session-validity checks
  (`auth.IsValidSession` / `IsValidTemporarySession`): if Redis can't be
  reached, the session is treated as invalid rather than valid. A Redis
  outage should degrade to "everyone gets logged out," not "auth checks
  stop happening."
- **CORS** echoes back only origins present in `ALLOWED_ORIGINS`
  (`utils.IsOriginAllowed`); an unlisted origin gets no
  `Access-Control-Allow-Origin` header at all, rather than a wildcard or a
  reflected-without-checking origin.
- **JSON decoding** rejects unknown fields and trailing data
  (`utils.DecodeJSONHandler`), and every request body is capped (default 8
  KB) via `http.MaxBytesReader` before it's touched.
- **Rate limiting runs in two layers on purpose**
  (`internal/middleware/rate_limit.go`): an IP-keyed limit wraps everything,
  including requests that fail JWT auth, so a bad-token flood against a
  protected route is still throttled; a second, user-ID-keyed limit runs
  *after* JWT auth for the requests that pass it, so accounts don't share a
  budget just because they're behind the same IP. Reordering these two
  instead of layering them (i.e. moving user-based limiting first) would
  quietly exempt every auth-failure request from rate limiting — that
  tradeoff is documented in the code because it's easy to "fix" the wrong
  way.

## Not implemented

The database schema (`db/migrations/001_init.up.sql`) already has tables for
several features the API doesn't expose yet — they were designed for, not
retrofitted:

- **Password reset** (`password_resets` table, with backup codes and a
  `source` enum for web/mobile/admin-initiated resets)
- **MFA** (`mfa_factors` table: TOTP/SMS/email factors, with a trigger
  preventing more than one TOTP factor per user)
- **SSO** (`auth_identities.provider` already supports `google`/`apple`
  alongside `email`; only the `email` provider has a working code path)
- **Admin actions** (`audit_logs` table, `moderator`/`admin` roles, and
  triggers preventing admin deletion/demotion are all in place; there's no
  admin API surface yet)
- **Scheduled maintenance** — `db/migrations/004_revoke_triggers.up.sql`
  defines SQL functions (`revoke_expired_sessions`,
  `remove_old_login_logs`, etc.) meant to be run on a schedule (cron, a
  Postgres extension like `pg_cron`, or an app-level job); nothing currently
  invokes them, so these tables will grow unbounded without an operator
  wiring one up.

If you build on this repo, those are the natural next pieces — the schema,
audit triggers, and error-code registry were already shaped with them in
mind.

## Testing

### Unit tests

No external dependencies (Postgres/Redis/Docker not required):

```bash
go test ./...
```

Covers password hashing/pepper rotation, JWT signing/parsing (including
algorithm-confusion and expired-token handling), input validation, JSON
decoding, config parsing/key loading (including the encrypted-private-key
path and a handful of `log.Fatal` branches exercised via the standard
subprocess re-exec idiom), the CORS/security-header/rate-limit middleware
logic (both the IP and per-user layers), and email rendering/sending (the
Resend client is redirected at a local `httptest.Server` via its exported
`BaseURL` field — no real network access, no mocking library needed).

Redis-touching code that doesn't need a real Postgres (`internal/auth/session.go`,
`otp_code.go`) is tested against [miniredis](https://github.com/alicebob/miniredis)
— a real `*redis.Client` pointed at an in-memory server — rather than
pushed into the Docker-gated suite, so it stays fast or CI-friendly without
losing real-Redis-client behavior.

### Integration tests

Exercise the real signup → login → refresh → logout lifecycle (lockout,
refresh-token reuse detection, pepper-rotation rehashing, and
`StartEmailVerification`'s email-taken/regen-window logic) against real
Postgres and Redis via [testcontainers-go](https://golang.testcontainers.org/).
Requires a working Docker (or Podman, via testcontainers' compatibility
mode) daemon.

This is also the **only** layer that drives requests through the real HTTP
stack — `internal/handlers`, `internal/middleware/{jwt,rate_limit,timeout}.go`,
and route registration all have zero coverage anywhere else, since every
other test calls service functions directly. `http_server_test.go` builds
the exact same `handlers.NewHandler` production code uses and serves it via
`httptest.Server`, covering: open-route auth bypass, protected-route
rejection of missing/malformed/tampered/expired/revoked tokens, the
refresh-token route's special expired-access-token acceptance, temp-JWT-vs-
normal-token cross rejection, CORS/security headers and OPTIONS preflight
on real responses, a full lifecycle over real HTTP (including post-logout
refresh rejection), 404/405 shape, rate-limit-exceeded, request-body-size
enforcement, and content-type enforcement.

These live in **their own nested Go module** (`test/integration/go.mod`)
specifically so testcontainers-go's dependency tree (a Docker client,
OpenTelemetry, etc.) never appears in the main module's `go.mod` — nobody
reading or building this service needs those dependencies unless they're
running this suite.

```bash
cd test/integration
go test ./...
```

## Database

Migrations are plain SQL, applied with [golang-migrate](https://github.com/golang-migrate/migrate)
via the `migrate-up`/`migrate-down` services in `docker-compose.yml`:

```bash
docker compose run --rm migrate-up
docker compose run --rm migrate-down   # reverts everything
```

Queries are hand-written SQL in `db/queries/*.sql` (the source of truth),
compiled to type-safe Go via [sqlc](https://sqlc.dev/):

```bash
go install github.com/sqlc-dev/sqlc/cmd/sqlc@v1.29.0
sqlc generate
```

Never hand-edit files under `internal/db/postgres/*.sql.go` — they're
regenerated wholesale and any manual changes will be silently lost. Add a
query to the relevant `db/queries/*.sql` file and regenerate instead.

## Useful dev commands

Connect to the running containers:

```bash
docker exec -it auth_postgres psql -U admin -d auth
docker exec -it auth_redis redis-cli
```

## License

[MIT](LICENSE)
