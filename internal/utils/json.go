package utils

import (
	"edibubble-api/config"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/getsentry/sentry-go"
	"go.uber.org/zap"
)

// Custom error messages for response handling
var (
	ErrRequestTooLarge = errors.New("request body too large")
	ErrMalformedJSON   = errors.New("malformed JSON")
	ErrEmptyBody       = errors.New("request body is empty")
	ErrExtraData       = errors.New("request body must only contain a single JSON object")
)

// Default maximum amount of bytes for JSON request bodies
const defaultMaxJSONBytes int64 = 8 << 10 // 8 KB

// Handle any JSON response with proper headers and formatting.
func JSONResponse(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	var output []byte
	var err error

	if config.Loaded.Env == "development" {
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

// decodeJSONBody decodes JSON from request with a max size limit.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}, maxBytes int64) error {
	// Limit the size of the request body
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		var syntaxError *json.SyntaxError
		var unmarshalTypeError *json.UnmarshalTypeError
		switch {
		case errors.Is(err, io.EOF):
			return ErrEmptyBody
		case errors.As(err, &syntaxError):
			return ErrMalformedJSON
		case errors.As(err, &unmarshalTypeError):
			return ErrMalformedJSON
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			return ErrMalformedJSON
		case strings.Contains(err.Error(), "http: request body too large"):
			return ErrRequestTooLarge
		default:
			return err
		}
	}

	// Check for extra JSON data
	if decoder.More() {
		return ErrExtraData
	}

	return nil
}

// DecodeJSONHandler attempts to decode the request body into dst and sends an appropriate error response on failure.
// Returns true on success, false on failure (error already written to response).
func DecodeJSONHandler(w http.ResponseWriter, r *http.Request, dst interface{}, maxBytes ...int64) bool {
	size := defaultMaxJSONBytes
	if len(maxBytes) > 0 {
		size = maxBytes[0]
	}
	err := decodeJSONBody(w, r, dst, size)
	if err == nil {
		return true
	}

	// Map custom errors to HTTP status codes
	var status int
	switch err {
	case ErrRequestTooLarge:
		status = http.StatusRequestEntityTooLarge // 413
	case ErrMalformedJSON, ErrExtraData, ErrEmptyBody:
		status = http.StatusBadRequest // 400
	default:
		status = http.StatusInternalServerError // unexpected error
	}

	// Log the error
	ctx := r.Context()
	LogWarn(ctx, "Failed to decode JSON request",
		zap.String("error", err.Error()),
	)
	sentry.CaptureException(err)

	// Send the error response
	JSONError(w, status, err.Error())
	return false
}
