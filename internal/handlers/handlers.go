package handlers

import (
	"edibubble-api/internal/server"
)

type Handlers struct {
	Svcs *server.Services
}

func New(svcs *server.Services) *Handlers {
	return &Handlers{Svcs: svcs}
}
