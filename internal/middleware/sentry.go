package middleware

import (
	"net/http"
	"time"

	"github.com/getsentry/sentry-go"
)

func SentryRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				sessionID := ""
				if v := r.Context().Value("session_id"); v != nil {
					sessionID, _ = v.(string)
				}
				sentry.WithScope(func(scope *sentry.Scope) {
					scope.SetTag("session_id", sessionID)
					scope.SetTag("path", r.URL.Path)
					scope.SetUser(sentry.User{IPAddress: r.RemoteAddr})
					sentry.CurrentHub().Recover(err)
					sentry.Flush(time.Second * 2)
				})
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
