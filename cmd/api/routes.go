package main

import (
	"net/http"
	"github.com/julienschmidt/httprouter"
)

func (app *application) routes() http.Handler {
	router := httprouter.New()

	router.HandlerFunc(http.MethodGet, "/v1/healthcheck", app.healthcheckHandler)
	router.HandlerFunc(http.MethodPost, "/v1/restaurant", app.createRestaurantHandler)
	router.HandlerFunc(http.MethodGet, "/v1/restaurant/:id", app.getRestaurantHandler)

	return router
}