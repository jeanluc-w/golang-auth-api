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
	// Write the error response with the helper and default to a 500 Internal Server Error
	// if that fails
	err := app.writeJSON(w, status, envelope{"error": message}, nil)
	if err != nil {
		app.logError(r, err)
		w.WriteHeader(500)
	}
}

// 500 response with a message
func (app *application) serverErrorResponse(w http.ResponseWriter, r *http.Request, err error) {
	app.logError(r, err)

	message := "the server encountered a problem and could not process your request"
	app.errorResponse(w, r, http.StatusInternalServerError, message)
}

// 404 error response
func (app *application) notFoundResponse(w http.ResponseWriter, r *http.Request) {
	message := "the requested resource could not be found"
	app.errorResponse(w, r, http.StatusNotFound, message)
}

// 405 error responses
func (app *application) methodNotAllowedResponse(w http.ResponseWriter, r *http.Request) {
	message := fmt.Sprintf("the %s method is not supported for this resource", r.Method)
	app.errorResponse(w, r, http.StatusNotFound, message)
}

// 400 error responses
func (app *application) badRequestResponse(w http.ResponseWriter, r *http.Request, err error) {
	app.errorResponse(w, r, http.StatusBadRequest, err.Error())
}

// 422 error responses
func (app *application) failedValidationResponse(w http.ResponseWriter, r *http.Request, errors map[string]string) {
	app.errorResponse(w, r, http.StatusUnprocessableEntity, errors)
}

// 401 error responses when the authentication is missing
func (app *application) missingAuthenticationResponse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", "Bearer")

	message := "missing or invalid authorization token"
	app.errorResponse(w, r, http.StatusUnauthorized, message)
}

// 401 error response to let them a user they need to be authenticated
func (app *application) authenticationRequiredResponse(w http.ResponseWriter, r *http.Request) {
	message := "you must be authenticated to access this resource"
	app.errorResponse(w, r, http.StatusUnauthorized, message)
}

// 403 error response when the request was properly formatted, but server wouldn't complete (i.e. duplicate records)
func (app *application) requestDeniedByServerResponse(w http.ResponseWriter, r *http.Request, err error) {
	app.errorResponse(w, r, http.StatusBadRequest, err.Error())
}

// 403 error responses when session authorization failed
func (app *application) sessionFailedAuthorizationResponse(w http.ResponseWriter, r *http.Request) {
	message := "session is invalid or expired"
	app.errorResponse(w, r, http.StatusForbidden, message)
}
