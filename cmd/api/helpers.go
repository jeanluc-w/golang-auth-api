package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/julienschmidt/httprouter"
)

type envelope map[string]any

// Returns either the environment variable value or an empty string
func getEnv(key string, fallback string) string {
	response := os.Getenv(key)
	if len(key) == 0 {
		return fallback
	}
	return response
}

// Function to easily create our JSON responses. This takes the destination
// http.ResponseWriter, the HTTP status code to send, the data to encode to JSON, and a
// header map containing any additional HTTP headers we want to include in the response
func (app *application) writeJSON(w http.ResponseWriter, status int, data envelope, headers http.Header) error {
	// Convert the data to JSON
	json, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	// Add a newline so it looks clean if we're pulling the endpoint in a terminal
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
func (app *application) readIDParam(r *http.Request) (int64, error) {
	params := httprouter.ParamsFromContext(r.Context())

	id, err := strconv.ParseInt(params.ByName("id"), 10, 64)
	if err != nil || id < 1 {
		return 0, errors.New("invalid id parameter")
	}

	return id, nil
}

func (app *application) readJSON(w http.ResponseWriter, r *http.Request, input any) error {
	// Limit the size of the request body to 1MB
	maxBytes := 1_048_576
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes))
	// Initialize the decoder to force request bodies to only include required fields before being processed
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(input)
	if err != nil {
		// If an error was caught, check what error ocurred
		var syntaxError *json.SyntaxError
		var unmarshalTypeError *json.UnmarshalTypeError
		var invalidUnmarshalError *json.InvalidUnmarshalError
		var maxBytesError *http.MaxBytesError
		// Return the appropriate error response based on what ocurred
		switch {
		// User request body is incorrect
		case errors.As(err, &syntaxError):
			return fmt.Errorf("body contains badly-formed JSON (at character %d)", syntaxError.Offset)

		// User request body is incorrect (pt 2)
		case errors.Is(err, io.ErrUnexpectedEOF):
			return errors.New("body contains badly-formed JSON")

		// Request body had an extra field. Error comes in as "json: unknown field name <name>"
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			fieldName := strings.TrimPrefix(err.Error(), "json: unknown field ")
			return fmt.Errorf("body contains unknown key %s", fieldName)

		// Request body exceeded the size limit
		case errors.As(err, &maxBytesError):
			return fmt.Errorf("body must not be larger than %d bytes", maxBytesError.Limit)

		// JSON value provided isn't appropriate for the GO type we're attempting to parse it as
		case errors.As(err, &unmarshalTypeError):
			if unmarshalTypeError.Field != "" {
				return fmt.Errorf("body contains incorrect JSON type for field %q", unmarshalTypeError.Field)
			}
			return fmt.Errorf("body contains incorrect JSON type (at character %d)", unmarshalTypeError.Offset)

		// Request body is empty
		case errors.Is(err, io.EOF):
			return errors.New("body must not be empty")

		// Our code is parsing it wrong (our fault)
		case errors.As(err, &invalidUnmarshalError):
			panic(err)
		// For all other scenarios, just return the error
		default:
			return err
		}
	}

	// Call the decoder again against an empty struct to see if the request body included more than one JSON body.
	// If the error is EOF, then we know it was only one JSON body in the request.  If there's more, then they tried
	// sending extra information.
	err = dec.Decode(&struct{}{})
	if !errors.Is(err, io.EOF) {
		return errors.New("body must only contain a single JSON value")
	}
	return nil
}
