package utils

import (
	"encoding/json"
	"net/http"
	"os"
)

// Use a global toggle for pretty output in development
var prettyPrint = os.Getenv("ENV") == "development"

// Handle any JSON response with proper headers and formatting.
func JSONResponse(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	var output []byte
	var err error

	if prettyPrint {
		output, err = json.MarshalIndent(payload, "", "  ")
	} else {
		output, err = json.Marshal(payload)
	}

	if err != nil {
		// fallback to basic error response
		http.Error(w, `{"error":"internal json encoding error"}`, http.StatusInternalServerError)
		return
	}

	_, _ = w.Write(output)
}

// Simplified error response handler
func JSONError(w http.ResponseWriter, status int, message string) {
	JSONResponse(w, status, map[string]string{
		"error": message,
	})
}
