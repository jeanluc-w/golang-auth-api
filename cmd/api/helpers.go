package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/julienschmidt/httprouter"
)

// Function to easily create our JSON responses. Parameters are
// the destination http.ResponseWriter, the HTTP status code to send, the data to 
// encode in JSON, and a header map containing additional HTTP headers
func (app *application) writeJSON(w http.ResponseWriter, status int, data any, headers http.Header) error {
	json, err := json.Marshal(data)
	if err != nil {
		return err
	}
	// Add a newline so it looks clean if we're testing the endpoint in a terminal
	json = append(json, '\n')
	// Loop through and add the custom headers to the response object
	for key, value := range headers {
		w.Header()[key] = value
	}
	// Add the Content-Type header and status code before sending the response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(json)

	return nil
}

// Retrieve the "id" URL parameter from the current request context, then convert it to
// an integer and return it. If the operation isn't successful, return 0 and an error. 
func (app *application) readIdParam(r *http.Request) (int64, error) {
	params := httprouter.ParamsFromContext(r.Context())

	id, err := strconv.ParseInt(params.ByName("id"), 10, 64)
	if err != nil || id < 1 {
		return 0, errors.New("invalid id parameter")
	}

	return id, nil
}