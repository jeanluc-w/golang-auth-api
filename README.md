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


# Running SQL Commands on the container
Example:
```
docker exec -it edibubble_postgres psql -U admin -d edibubble -c "SELECT * FROM users;"
```

# Connect to Redis CLI
```
docker exec -it edibubble_redis redis-cli
```

Quick Commands
1. `ping` - Checks if Redis is responsive. It should return `PONG`.
1. `keys *` - Lists all the keys in the db.
1. `info` - Provides information about the Redis server such as memory usage, connected clients, and persistence details.
1. `dbsize` - Returns the number of keys in the currently selected database.