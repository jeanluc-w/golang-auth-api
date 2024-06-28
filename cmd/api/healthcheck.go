package main

import (
	"net/http"
)

// Simple API that writes a plain-text response with information about the
// app status, environment (dev|stage|prod), and version.
func (app *application) healthcheckHandler(w http.ResponseWriter, r *http.Request) {
	// Create the JSON object
	data := map[string]string{
		"status":      "available",
		"environment": app.config.env,
		"version":     version,
	}
	// Generate and return the JSON response
	err := app.writeJSON(w, http.StatusOK, data, nil)
	// Return an error response if the response could be sent
	if err != nil {
		app.logger.Error(err.Error())
		http.Error(w, "The server encountered a problem and could not process your request", http.StatusInternalServerError)
	}
}
