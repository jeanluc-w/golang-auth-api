package handlers

import (
	"auth-api/internal/server"
)

type Handlers struct {
	Svcs *server.Services
}

func New(svcs *server.Services) *Handlers {
	return &Handlers{Svcs: svcs}
}
