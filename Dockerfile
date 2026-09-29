# syntax=docker/dockerfile:1

# --- Build stage -------------------------------------------------------
# Uses the Go version/toolchain pinned in go.mod (via GOTOOLCHAIN=auto,
# the default) so the binary is built with exactly what CI and local
# development use.
FROM golang:1.26-alpine AS builder

WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: every dependency here (pgx, argon2, etc.) is pure Go, so a
# static binary is possible — that's what lets the final stage be
# `distroless/static` with no libc at all, shrinking the attack surface.
# Both binaries share this one image: the server (default ENTRYPOINT) and
# the one-shot maintenance job (cmd/cron), invoked by overriding the
# container command — see the README's "Maintenance / cron jobs" section.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/auth-api ./cmd
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/auth-cron ./cmd/cron

# --- Runtime stage -------------------------------------------------------
# distroless/static has no shell, no package manager, and no other binaries
# to pivot to if the app is ever compromised — just the binaries and CA
# certs (needed for outbound HTTPS to Resend/Sentry). It also runs as a
# non-root UID (65532) by default via the "nonroot" tag.
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app
COPY --from=builder /out/auth-api /app/auth-api
COPY --from=builder /out/auth-cron /app/auth-cron

# JWT keys, and anything else read from disk via env vars pointing at file
# paths (JWT_PRIVATE_KEY_FILE / JWT_PUBLIC_KEY_FILE), are expected to be
# mounted in at runtime — never baked into the image. See .copy.env for the
# full list of required environment variables.
EXPOSE 8080

USER nonroot:nonroot
ENTRYPOINT ["/app/auth-api"]
