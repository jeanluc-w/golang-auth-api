package main
import (
	"fmt"
	"net/http"
)

// Simple API that writes a plain-text response with information about the
// app status, environment (dev|stage|prod), and version.
func (app *application) healthcheckHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Status: Available")
	fmt.Fprintf(w, "Environment: %s\n", app.config.env)
	fmt.Fprintf(w, "Version: %s\n", version)
}