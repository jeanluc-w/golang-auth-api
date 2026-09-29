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
- **Password reset** via a single-use, hashed, time-limited emailed token;
  enumeration-resistant (the response never varies based on whether the
  email has an account), and completing a reset revokes every existing
  session on the account, in both Postgres and Redis.
- **Authenticated password change**, given the current password — unlike a
  reset, it revokes every *other* session but leaves the one making the
  request alone.
- **TOTP-based MFA** (RFC 6238, compatible with Google Authenticator/Authy/
  1Password/etc.): secrets encrypted at rest (AES-256-GCM, a key never
  itself stored in the database), constant-time code comparison, anti-replay
  (a code's time-step can't be reused even within its own validity window),
  and one-time recovery codes (only their hash is persisted) for when the
  device is unavailable. Gates login via a short-lived challenge token, not
  a second password.
- **SSO (Google, Apple)** via OIDC ID token verification against each
  provider's live JWKS (signature, issuer, audience, expiry — see
  `internal/auth/oidc.go`), with a deliberately conservative account-linking
  policy: an unverified provider email is always rejected, and an email
  that already has an account under a different identity is rejected as a
  conflict rather than silently auto-linked. See
  [Security notes](#security-notes) for the full rationale.
- **Scheduled maintenance jobs** (`cmd/cron`) that expire old password
  reset tokens/login logs/unverified MFA factors and revoke stale sessions
  — a one-shot binary meant for an external scheduler, not a background
  goroutine in the server itself. See [Maintenance / cron jobs](#maintenance--cron-jobs).
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
cmd/cron/main.go        one-shot maintenance job runner (see Maintenance / cron jobs)
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
| POST   | `/auth/v1/request-password-reset`   | none                   | Email a password reset token, if the account exists and is usable |
| POST   | `/auth/v1/reset-password`           | reset token in body    | Set a new password and revoke every session on the account |
| POST   | `/auth/v1/change-password`          | access JWT             | Change password given the current one; revokes every *other* session |
| POST   | `/auth/v1/mfa/enroll`               | access JWT             | Start TOTP enrollment; returns a secret + QR provisioning URI |
| POST   | `/auth/v1/mfa/verify`               | access JWT             | Confirm enrollment with a code; activates MFA and returns recovery codes |
| POST   | `/auth/v1/mfa/disable`              | access JWT + current password | Turn MFA off |
| POST   | `/auth/v1/mfa/verify-login`         | MFA challenge token in body | Complete an MFA-gated login with a TOTP or recovery code |
| POST   | `/auth/v1/sso/google`               | none                   | Log in or sign up with a Google ID token |
| POST   | `/auth/v1/sso/apple`                | none                   | Log in or sign up with an Apple identity token |

A `login` response for an MFA-enabled account is `{"mfa_required": true, "challenge_token": "..."}` instead of tokens — submit that token plus a code to `mfa/verify-login` to actually complete the login.

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

### 5. (Optional) Build the production image

A multi-stage [`Dockerfile`](Dockerfile) builds a static (`CGO_ENABLED=0`)
binary and ships it on `distroless/static-debian12:nonroot` — no shell, no
package manager, non-root by default. JWT keys and other file-based secrets
are mounted in at runtime, never baked into the image.

```bash
docker build -t auth-api .
# JWT_*_KEY_FILE in .env defaults to ./secrets/..., resolved against the
# container's /app working directory — hence mounting to /app/secrets here.
# DATABASE_URL/REDIS_ADDR pointing at "localhost" also won't reach services
# running on the host from inside the container; adjust those for wherever
# Postgres/Redis actually are in your setup (a Docker network, a cloud DB, etc).
docker run --rm -p 8080:8080 --env-file .env -v "$(pwd)/secrets:/app/secrets:ro" auth-api
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
| `PASSWORD_RESET_TOKEN_TTL_MINUTES` | no | `30` | how long a reset token/link stays valid |
| `PASSWORD_RESET_URL` | no | empty | frontend reset-password page; if set, the reset email links to `<this>?token=<raw token>`; if empty, the email states the raw token instead |
| `MFA_ENCRYPTION_KEY` | yes | — | 32 raw bytes, base64-encoded (`openssl rand -base64 32`); encrypts TOTP secrets at rest (AES-256-GCM) |
| `MFA_ISSUER` | no | `auth-api` | name shown in authenticator apps next to the account |
| `GOOGLE_CLIENT_ID` | no | empty | enables `POST /auth/v1/sso/google` when set |
| `APPLE_CLIENT_ID` | no | empty | enables `POST /auth/v1/sso/apple` when set |
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
- **Password reset is enumeration-resistant by design**: unlike signup's
  `StartEmailVerification` (which reveals `email_is_taken` — an accepted
  tradeoff there), `RequestPasswordReset` returns the exact same generic
  success response whether the email has an account, belongs to a
  deleted/banned/disabled one, or is still within its 1-minute regeneration
  cooldown. Only the reset *token* itself (`GetActivePasswordReset`,
  `ResetPassword`) — a high-entropy secret the caller already has to
  possess — is allowed to produce a specific `invalid_or_expired_token`
  error, since that doesn't leak anything about which accounts exist. See
  `services.RequestPasswordReset`'s doc comment for the one narrow, deliberate
  exception (a genuine internal/email-sending failure still surfaces as
  `internal_server_error`).
- **Completing a password reset revokes every session on the account** —
  in both Postgres (`RevokeAllUserSessions`, checked by the refresh-token
  flow) and Redis (`auth.DeleteSession` per active session ID, checked by
  access-token verification) — and the token/password-update/session-revoke
  sequence runs in one transaction (`postgres.CompletePasswordReset`) so a
  crash mid-reset can't leave the token consumed without the password
  actually changing.
- **Changing your password only revokes *other* sessions**
  (`postgres.CompletePasswordChange` / `RevokeAllOtherUserSessions`),
  deliberately unlike a reset: the caller already re-proved their identity
  with the current password in this very request, so there's no reason to
  also sign out the device making it. A reset has no such proof (the emailed
  token is the only credential involved), so it revokes everything.
  Attempting to "change" to the same password is rejected outright
  (`new_password_matches_current`) rather than silently no-op'd.
- **MFA secrets are encrypted at rest, not just access-controlled**
  (`auth.EncryptMFASecret`, AES-256-GCM, key in `MFA_ENCRYPTION_KEY` — never
  in the database, same principle as password peppers). Unlike a password,
  a TOTP secret can't be hashed: verifying a code requires the plaintext
  back, so a stolen DB dump must not be enough on its own to generate valid
  codes for every enrolled account.
- **MFA codes can't be replayed within their own validity window** —
  `mfa_factors.last_used_step` records the exact 30-second time-step a code
  last succeeded on, and `auth.ValidateTOTPCode` rejects that step (and
  anything before it) even though the code itself would otherwise still be
  cryptographically valid for the rest of that window. Recovery codes are
  single-use for the same reason, tracked via `used_at` rather than a step.
- **MFA disable requires the current password**, not just a valid session —
  turning off a security control must not be possible with a stolen/replayed
  access token alone, since an attacker holding one still doesn't know the
  password.
- **SSO account-linking is deliberately conservative** (`services.SSOLogin`):
  an ID token whose `email_verified` claim is false is refused outright,
  whether the flow would have created a new account or logged into an
  existing one — an SSO login is only ever as trustworthy as the provider's
  own claim that the caller controls that email. And when a *verified*
  email already has an account under a different identity (a different SSO
  provider, or email/password), this service refuses that too
  (`sso_account_conflict`) rather than silently merging the two accounts.
  Auto-linking on a verified-email match is a legitimate, common choice
  other products make — it's just a product decision this repo didn't want
  to make silently on your behalf, since merging accounts without an
  explicit action from the user on either side is the kind of thing that's
  much easier to get subtly wrong than it looks. A "connect this provider
  while already authenticated" flow is the natural way to let a user
  perform that link deliberately; it isn't implemented here (see
  [Not implemented](#not-implemented)).
- **SSO ID tokens are verified against each provider's live, cached JWKS**
  (`internal/auth/oidc.go`, via
  [`keyfunc`](https://github.com/MicahParks/keyfunc) rather than hand-rolled
  JWK parsing/rotation) — signature, issuer, audience (your
  `GOOGLE_CLIENT_ID`/`APPLE_CLIENT_ID`), and expiry are all checked before
  any claim in the token is trusted. Apple's identity tokens send
  `email_verified` as the JSON *string* `"true"`/`"false"` rather than a
  JSON boolean (a real, documented quirk); `auth.VerifyOIDCToken` handles
  both encodings rather than only the spec-correct one.
- **Dependencies are scanned with [`govulncheck`](https://go.dev/blog/vuln)**
  in CI (and via `make vulncheck` locally), which does call-graph analysis
  rather than flagging every CVE in every transitive dependency regardless
  of whether the vulnerable code path is ever reached. This caught a real,
  reachable SQL-injection CVE in an earlier `pgx` version during development
  (GO-2026-5004, fixed by upgrading to `pgx v5.9.2`) — worth keeping in CI
  rather than a one-time check, since new CVEs get disclosed against
  dependencies you never touched.

## Not implemented

The database schema (`db/migrations/001_init.up.sql`) already has tables for
a few features the API still doesn't expose — they were designed for, not
retrofitted:

- **MFA via SMS or email** (`mfa_factors.type` supports them, and the
  `UNIQUE(user_id, type)` constraint means a user could have one of each
  alongside TOTP) — TOTP is the only type with a working code path. SMS
  needs a paid provider integration (Twilio et al.) this repo deliberately
  doesn't take a dependency on; email MFA would reuse the existing
  Resend/template plumbing but is a meaningfully weaker factor (same inbox
  as password reset) and wasn't worth adding just to say two exist.
- **Admin actions** (`audit_logs` table, `moderator`/`admin` roles, and
  triggers preventing admin deletion/demotion are all in place; there's no
  admin API surface yet)
- **Linking an additional SSO provider (or email/password) to an
  already-authenticated account** — `services.SSOLogin` currently rejects
  an SSO login whose email already has an account under a different
  identity (`SSOAccountConflict`) rather than linking it, specifically
  because there's no such flow yet for the user to authorize that link
  themselves. See [Security notes](#security-notes) for the full reasoning.

If you build on this repo, the items above are the natural next pieces —
the schema, audit triggers, and error-code registry were already shaped
with them in mind.

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
`otp_code.go`, `jwt.go`'s token issuance/verification, and
`internal/middleware/jwt.go`) is tested against
[miniredis](https://github.com/alicebob/miniredis) — a real `*redis.Client`
pointed at an in-memory server — rather than pushed into the Docker-gated
suite, so it stays fast and CI-friendly without losing real-Redis-client
behavior. This is how the core auth gate (`JWTMiddleware`, token
issuance/rotation, session revocation) gets exercised at the unit level, not
just end-to-end.

`internal/middleware/logging.go` (request logging + panic recovery) and
`timeout.go` are unit-tested directly too, using `zaptest/observer` to
assert on log output and a slow handler to trigger the timeout — no Docker
or real server needed for either.

MFA's crypto core (`internal/auth/mfa_encryption.go`, `mfa_totp.go`) and SSO's
token verification (`internal/auth/oidc.go`) are also fully unit-tested with
no Postgres/Redis/Docker: AES-GCM round-trip/tamper/wrong-key cases for
secret encryption; TOTP code generation, ±1-step clock-drift tolerance, and
same-step replay rejection using real `pquerna/otp` codes; and OIDC
verification against a real, locally-generated RSA keypair served from a
fake JWKS `httptest.Server` (same "redirect at a local server" trick used
for Resend) — covering wrong audience, wrong issuer, expired, tampered, and
untrusted-signing-key rejection, plus Apple's `email_verified`-as-a-JSON-
string quirk.

### Integration tests

Exercise the real signup → login → refresh → logout lifecycle (lockout,
refresh-token reuse detection, pepper-rotation rehashing, and
`StartEmailVerification`'s email-taken/regen-window logic), the full
password-reset flow (enumeration-resistance, cooldown, expired/reused/unknown
tokens, and that a reset actually revokes every prior session in both
Postgres and Redis — `password_reset_test.go`), authenticated password
change (`change_password_test.go`), the full MFA lifecycle (enroll → verify
→ MFA-gated login via TOTP or a recovery code → disable, plus wrong-code and
wrong-password rejection — `mfa_test.go`), SSO's account-linking policy
(new account, existing login, email-not-verified, email-conflict across
providers, username-collision suffixing — `sso_test.go`), and all six
`RunMaintenance` cleanup jobs seeded with backdated rows so each cutoff is
tested precisely (`maintenance_test.go`) — all against real Postgres and
Redis via [testcontainers-go](https://golang.testcontainers.org/). Requires
a working Docker (or Podman, via testcontainers' compatibility mode)
daemon.

SSO's integration tests call `services.SSOLogin` with already-verified
`auth.OIDCClaims` directly rather than real ID tokens — token
signature/issuer/audience verification is the crypto-sensitive part and is
already covered in detail at the unit level (above) with no need for
Postgres; what's actually DB-dependent, and what these tests cover, is the
account-linking/conflict/creation policy layered on top of it.

This is also the **only** layer that drives requests through the real HTTP
stack — `internal/handlers`, `internal/services`, `internal/db/postgres`,
and route registration have no coverage anywhere else, since unit tests
either call package-internal logic directly or don't need a real
database/HTTP round trip at all. `http_server_test.go` builds the exact same
`handlers.NewHandler` production code uses and serves it via
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

### CI and git hooks

Every push and pull request against `dev`/`main` runs
[`.github/workflows/ci.yml`](.github/workflows/ci.yml): `go mod tidy`/`gofmt`
drift checks, `go vet`, a full build, the unit test suite (`-race`), and the
Docker-backed integration suite, each as a separate required job. To make
these required PR checks (not just informational), turn on branch protection
for `dev`/`main` in **Settings → Branches → Add rule** and require the `test`
and `integration-test` status checks before merging — this repo can't enable
that setting on its own, since it's a GitHub repo-admin action rather than a
file in the repo.

The same checks are available locally through the `Makefile`:

```bash
make hooks             # one-time per clone: installs the pre-commit hook below
make tidy fmt vet test  # what CI runs against the main module
make test-integration   # what CI runs against test/integration (needs Docker)
make ci                 # everything, in one shot
```

`make hooks` points git at [`.githooks/pre-commit`](.githooks/pre-commit),
which runs gofmt/vet/tidy/test for both modules before every commit —
including the integration suite, automatically, whenever Docker is
reachable (skipped with a warning otherwise, since forcing container
start-up on every commit would be too slow for a tight edit loop). Like any
client-side hook it's opt-in per clone and can be bypassed with
`git commit --no-verify`; the CI workflow above is the actual, unbypassable
gate.

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

## Maintenance / cron jobs

`db/migrations/004_revoke_triggers.up.sql` defines six Postgres cleanup
functions (expire old password reset tokens, prune login-attempt history
older than 90 days, drop unverified MFA factors after 2 hours, revoke
expired/stale sessions, etc.) that nothing calls on its own — Postgres
functions don't schedule themselves. `cmd/cron` is a small binary
(`internal/services.RunMaintenance`) that runs all six once, logs each
job's result individually, and exits non-zero if any failed:

```bash
make cron                 # runs once, against DATABASE_URL from your env/.env
go run ./cmd/cron         # equivalent, if you'd rather not go through make
```

It's built into the same Docker image as the server
(`/app/auth-cron`, see [Dockerfile](Dockerfile)) and is meant to be invoked
by an external scheduler — nothing in this repo runs it on a timer itself.
For example, with plain crontab on a single host:

```cron
0 * * * * docker run --rm --env-file /path/to/.env auth-api /app/auth-cron
```

Or as a Kubernetes CronJob:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: auth-api-maintenance
spec:
  schedule: "0 * * * *"   # hourly; the jobs are cheap and idempotent, so more often is fine
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: maintenance
              image: auth-api:latest
              command: ["/app/auth-cron"]
              envFrom:
                - secretRef:
                    name: auth-api-env
          restartPolicy: OnFailure
```

## Useful dev commands

Connect to the running containers:

```bash
docker exec -it auth_postgres psql -U admin -d auth
docker exec -it auth_redis redis-cli
```

## License

[MIT](LICENSE)
