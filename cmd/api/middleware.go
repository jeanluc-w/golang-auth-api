package main

import (
	"edibubble/internal/data"
	"edibubble/internal/validator"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

func (app *application) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			// Check if Go has had a panic or not
			if err := recover(); err != nil {
				// If there was a panic, close the connection and return an error response
				w.Header().Set("Connection", "close")
				app.serverErrorResponse(w, r, fmt.Errorf("%s", err))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Default Authorization Header handler response for all calls.
func (app *application) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add a "Vary: Authorization" so caches know the response varies based on the request's
		// Authorization header.
		w.Header().Add("Vary", "Authorization")

		authHeader := r.Header.Get("Authorization")

		// If it's empty, pass an anonymous user into the context. The auth-protected API's will deny
		// when they check that the context doesn't contain an anonymous user.
		if authHeader == "" {
			r = app.contextSetUser(r, data.AnonymousUser)
			next.ServeHTTP(w, r)
			return
		}

		// Strip the session id from the Authorization Header.
		headerParts := strings.Split(authHeader, " ")
		if len(headerParts) != 2 || headerParts[0] != "Bearer" {
			app.missingAuthenticationResponse(w, r)
			return
		}
		sessionToken := headerParts[1]

		// Validate the sessionToken is a valid GUID
		v := validator.New()
		if data.ValidateSessionToken(v, sessionToken); !v.Valid() {
			app.missingAuthenticationResponse(w, r)
			return
		}

		user, err := app.models.User.GetUserID(sessionToken, app.logger)
		if err != nil {
			switch {
			case errors.Is(err, data.ErrNoRows):
				app.sessionFailedAuthorizationResponse(w, r)
			default:
				app.serverErrorResponse(w, r, err)
			}
			return
		}

		r = app.contextSetUser(r, user)
		next.ServeHTTP(w, r)
	})
}

// Specific authentication check function to deny anyone without proper sessions.
func (app *application) requireAuthenticatedUser(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := app.contextGetUser(r)

		if user.IsAnonymous() {
			app.authenticationRequiredResponse(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (app *application) enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		w.Header().Add("Vary", "Access-Control-Request-Method")

		origin := r.Header.Get("Origin")

		if origin != "" {
			for i := range app.config.cors.trustedOrigins {
				if origin == app.config.cors.trustedOrigins[i] {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
						w.Header().Set("Access-Control-Allow-Methods", "OPTIONS, PUT, PATCH, DELETE")
						w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
					}
					break
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}
