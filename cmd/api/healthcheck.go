package main
import (
	"fmt"
	"net/http"
)

// Simple API that writes a plain-text response with information about the
// app status, environment (dev|stage|prod), and version.
func (app *application) healthcheckHandler(w http.ResponseWriter, r *http.Request) {
	// Create the JSON body for the response
	body := `{"status": "available", "environment": %q, "version": %q}`
	body = fmt.Sprintf(body, app.config.env, version)
	// Set the content-type header to JSON
	w.Header().Set("Content-Type", "application/json")
	// Write the JSON to the HTTP response body
	w.Write([]byte(body))
}