# Overview

## Technology to Learn/Use

- Go: REST API Framework
- PostgreSQL with PostGIS: Hosted on Railway
- Redis: Caching and Real-Time Presence
- JWT: Authentication with Refresh Token Support
- pgx: Type-Safe DB Access
- Golang-Migrate: Schema Migrations
- Zap: Structured Logging
- Gorilla WebSockets: Real-Time Chat and Updates

# Starting Golang Locally 

## macOS/Linux:
Simply run `go run ./cmd/main` to start up the server.

## Windows:
If running into the Windows security popup, simply run `go build .\cmd\main; main.exe` so it will always run in the same folder, preventing the popup from repeated uses of running the program. Otherwise, `go run .\cmd\main` works as well but you'll get the "do you trust this program"


# SQL Commands on the Docker container
Example:
`docker exec -it edibubble_postgres psql -U admin -d edibubble -c "SELECT * FROM users;"`