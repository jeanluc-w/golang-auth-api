package main

import (
	"fmt"
	"net/http"
)

// Function to log the error message with the current request message
// and URL as attributes
func (app *application) logError(r *http.Request, err error) {
	var (
		method = r.Method
		uri    = r.URL.RequestURI()
	)

	app.logger.Error(err.Error(), "method", method, "uri", uri)
}

// Handler for formatting all error responses into JSON and defualting to a
// simple 500 if that fails
func (app *application) errorResponse(w http.ResponseWriter, r *http.Request, status int, message any) {
	errorRsp := envelope{"error": message}

	// Write the error response with the helper and default to a 500 Internal Server Error
	// if that fails
	err := app.writeJSON(w, status, errorRsp, nil)
	if err != nil {
		app.logError(r, err)
		w.WriteHeader(500)
	}
}

// Handler for logging the server error and sending a 500 response with a message
func (app *application) serverErrorResponse(w http.ResponseWriter, r *http.Request, err error) {
	app.logError(r, err)

	message := "The server encountered a problem and could not process your request"
	app.errorResponse(w, r, http.StatusInternalServerError, message)
}

// Handler for 404 error responses
func (app *application) notFoundResponse(w http.ResponseWriter, r *http.Request) {
	message := "the requested resource could not be found"
	app.errorResponse(w, r, http.StatusNotFound, message)
}

// Handler for 405 error responses
func (app *application) methodNotAllowedResponse(w http.ResponseWriter, r *http.Request) {
	message := fmt.Sprintf("the %s method is not supported for this resource", r.Method)
	app.errorResponse(w, r, http.StatusNotFound, message)
}
