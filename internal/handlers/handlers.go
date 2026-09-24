package handlers

import (
	"auth-api/internal/server"
)

// Handlers holds the shared services every HTTP handler method needs
// (DB pool, Redis client, email client, etc.), avoiding a global.
type Handlers struct {
	Svcs *server.Services
}

// New constructs the Handlers value that main.go registers routes against.
func New(svcs *server.Services) *Handlers {
	return &Handlers{Svcs: svcs}
}
