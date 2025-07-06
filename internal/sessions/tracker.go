package sessions

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

type keyType string

const sessionKey keyType = "session_id"

type Tracker struct {
	// Optional: store active sessions in memory or DB
}

func NewTracker() *Tracker {
	return &Tracker{}
}

func (t *Tracker) CreateSession(r *http.Request) string {
	return uuid.New().String()
}

func SessionMiddleware(t *Tracker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionID := r.Header.Get("X-Session-ID")
			if sessionID == "" {
				sessionID = t.CreateSession(r)
			}
			ctx := context.WithValue(r.Context(), sessionKey, sessionID)
			r = r.WithContext(ctx)
			w.Header().Set("X-Session-ID", sessionID)
			next.ServeHTTP(w, r)
		})
	}
}
