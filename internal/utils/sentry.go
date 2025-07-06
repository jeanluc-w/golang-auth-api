package utils

import (
	"net/http"

	"github.com/getsentry/sentry-go"
)

// Call this at the start of each handler to set Sentry context for the request/session.
func InitSentryScope(r *http.Request) {
	sentry.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetTag("path", r.URL.Path)
		scope.SetUser(sentry.User{IPAddress: r.RemoteAddr})
		if sessionData := r.Context().Value("session_id"); sessionData != nil {
			if sessionID, ok := sessionData.(string); ok {
				scope.SetTag("session_id", sessionID)
			}
		}
	})
}
