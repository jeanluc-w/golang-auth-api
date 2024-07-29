package main

import (
	"context"
	"edibubble/internal/data"
	"net/http"
)

type contextKey string

const userContextKey = contextKey("user")

// Sets the User struct in the request's context (either authenticated user or anonymous).
func (app *application) contextSetUser(r *http.Request, user *data.User) *http.Request {
	ctx := context.WithValue(r.Context(), userContextKey, user)
	return r.WithContext(ctx)
}

// Retrieves the User struct from the request's context. Panic if this is somehow missing.
func (app *application) contextGetUser(r *http.Request) *data.User {
	user, ok := r.Context().Value(userContextKey).(*data.User)
	if !ok {
		panic("missing user value in request context")
	}

	return user
}
