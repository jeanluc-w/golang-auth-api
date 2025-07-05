# Edibubble API

## Technology to Learn/Use

- Go: REST API Framework
- PostgreSQL with PostGIS: Hosted on Railway
- Redis: Caching and Real-Time Presence
- JWT: Authentication with Refresh Token Support
- pgx: Type-Safe DB Access
- Golang-Migrate: Schema Migrations
- Zap: Structured Logging
- Gorilla WebSockets: Real-Time Chat and Updates

# Installation

## macOS/Linux:
./scripts/setup.sh

## Windows (PowerShell):
.\scripts\setup.ps1

## Windows (Command Prompt):
scripts\setup.bat

# Folder Structure

## Overview

edibubble-api/
├── cmd/
│   └── server/               # Entry point (main.go)
│
├── config/                   # Config loading from .env, etc.
│
├── internal/                 # All app-specific code (not reusable outside)
│   ├── auth/                 # JWT, refresh tokens, email verification, SSO
│   ├── db/                   # DB access (sqlc/pgx wrappers, connection init)
│   ├── handlers/             # HTTP handlers (pure net/http)
│   │   ├── users.go
│   │   ├── auth.go
│   │   ├── restaurants.go
│   │   └── lists.go
│   ├── middleware/           # net/http middleware (auth, logging, CORS)
│   ├── models/               # sqlc-generated models (from .sqlc.yaml)
│   ├── redis/                # Redis clients and temp signup logic
│   └── services/             # Business logic (decoupled from transport)
│       ├── user_service.go
│       ├── auth_service.go
│       ├── restaurant_service.go
│       └── list_service.go
│
├── db/
│   ├── migrations/           # SQL files for golang-migrate
│   └── queries.sql           # Used by sqlc to generate code
│
├── scripts/                  # Dev scripts (migrations, seed, etc.)
│   └── migrate.sh
│
├── test/                     # Black-box/integration tests
│
├── .env
├── sqlc.yaml
├── go.mod
└── go.sum

## Breakdown

| Folder        | Purpose                                                                                                        |
| ------------- | -------------------------------------------------------------------------------------------------------------- |
| `cmd/server`  | Keeps the entry point clean and separate for future multiple services (e.g., a background job processor later) |
| `config/`     | Central place for environment variable loading and validation                                                  |
| `internal/`   | Isolated app logic; avoids polluting global namespace or accidentally exposing private logic to Go modules     |
| `auth/`       | All auth logic (JWT, password hashing, email/SSO provider logic) in one place                                  |
| `handlers/`   | Presentation layer (HTTP-specific request/response parsing)                                                    |
| `services/`   | Core business rules and use cases                                                                              |
| `db/`         | Owns schema and query generation via `sqlc`                                                                    |
| `redis/`      | Centralized logic for signup caching, future real-time presence, etc.                                          |
| `middleware/` | net/http interceptors, kept small and reusable                                                                 |
| `test/`       | Keeps test files out of `internal/` for clarity, but easily discoverable                                       |

## Later Implementations

| Folder       | Purpose                                                                      |
| ------------ | ---------------------------------------------------------------------------- |
| `docs/`      | API docs, diagrams                                                           |
| `assets/`    | Seed data, templates                                                         |
| `websocket/` | WebSocket handler logic (when you add live map / chat)                       |
| `jobs/`      | Background jobs (e.g., email sender, notification pusher)                    |
| `pkg/`       | Reusable utilities not specific to Edibubble (e.g., a custom logger wrapper) |


# REST APIs for Edibubble

***TODO: Update chart with these.***
- **Auth**: `/auth/signup`, `/auth/login`, `/auth/me`, `/auth/oauth/google`
- **Users**: `/users/:id`, `/users/me`, `/users/search`
- **Lists**: `/lists`, `/lists/:id`, `/lists/:id/restaurants`, `/lists/search`
- **Restaurants**: `/restaurants`, `/restaurants/:id`, geo+tag filters
- **Reviews**: `/reviews`, `/restaurants/:id/reviews`
- **Comments**: `/comments`, `/reviews/:id/comments`
- **Social**: `/follow/:id`, `/unfollow/:id`, `/feed`, `/friends`
- **Discovery**: `/search`, `/suggestions`, `/lists/:id/random`

| Method | URL Pattern                      | Go Handler                      | Purpose                                                          |
|--------|----------------------------------|---------------------------------|------------------------------------------------------------------|
| GET    | /v1/healthcheck                  | healthcheckHandler              | Check that the service is up and running.                        |
| POST   | /v1/set-username                 | setUsernameHandler              | Set a user's username.                                           |
| GET    | /v1/user/:id                     | getUserHandler                  | Get a user's profile information                                 |
| POST   | /v1/restaurant                   | createRestaurantHandler         | Create a new restaurant.                                         |
| GET    | /v1/restaurant/:id               | getRestaurantHandler            | Get the information of a restaurant.                             |
| PUT    | /v1/restaurant/:id               | editRestaurantHandler           | Edit the information of a restaurant.                            |
| DELETE | /v1/restaurant/:id               | deleteRestaurantHandler         | Delete a restaurant from the database.                           |
| POST   | /v1/list/restaurants             | createRestaurantListHandler     | Create a new list of restaurants for a user.                     |
| GET    | /v1/list/restaurants/:id         | getRestaurantListHandler        | Get the information of a restaurant list.                        |
| PUT    | /v1/list/restaurants/:id         | editRestaurantListHandler       | Update a user's restaurant list.                                 |
| DELETE | /v1/list/restaurants/:id         | deleteListHandler               | Delete a user's restaurant list.                                 |
| GET    | /v1/list/restaurants/:id/history | getRestaurantListHistoryHandler | Get the list's revision history so you know who made what edits. |


# Starting Golang Locally 

## macOS/Linux:
Simply run `go run cmd/server` to start up the server.

## Windows (Command Prompt):
If running into the Windows security popup, simply run `go build cmd/server && server.exe` so it will always run in the same folder, preventing the popup from repeated uses of running the program. Otherwise, `go run cmd/server` works as well

# Useful global config for github:

Do `git config --list --show-origin` to see where your global git config is located. Once found, add these lines to the bottom and replace the values for `your_git_username` and `you_git_PAT`:

```
[url "https://your_git_username:your_git_PAT@github.com/"]
  insteadof = https://github.com/
[url "https://your_git_username:your_git_PAT@github.com/"]
  insteadof = ssh://git@github.com/
[url "https://your_git_username:your_git_PAT@github.com/"]
  insteadof = git@github.com:
```