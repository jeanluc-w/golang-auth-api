package main

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func (app *application) routes() http.Handler {
	router := httprouter.New()

	router.NotFound = http.HandlerFunc(app.notFoundResponse)
	router.MethodNotAllowed = http.HandlerFunc(app.methodNotAllowedResponse)

	router.HandlerFunc(http.MethodGet, "/v1/healthcheck", app.healthcheckHandler)

	router.HandlerFunc(http.MethodGet, "/v1/user/:id", app.getUserHandler)
	router.HandlerFunc(http.MethodPost, "/v1/set-username", app.requireAuthenticatedUser(app.setUsernameHandler))
	//router.HandlerFunc(http.MethodPost, "/v1/restaurant", app.createRestaurantHandler)
	//router.HandlerFunc(http.MethodGet, "/v1/restaurant/:id", app.getRestaurantHandler)

	return app.recoverPanic(app.enableCORS(app.authenticate(router)))
}
