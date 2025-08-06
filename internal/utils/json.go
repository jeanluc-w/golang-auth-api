package utils

import (
	"edibubble-api/config"
	"edibubble-api/internal/entities"
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
	// Attempt to use the custom ResponseWriter if available
	rw := w
	// If it's our custom wrapper, set the status and the writer to that
	if mw, ok := w.(*entities.ResponseWriter); ok {
		mw.Status = status
		rw = mw
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)

	var output []byte
	var err error

	if config.Loaded.Env == "development" {
		output, err = json.MarshalIndent(payload, "", "  ")
	} else {
		output, err = json.Marshal(payload)
	}

	if err != nil {
		// fallback to basic error response
		http.Error(rw, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	_, _ = rw.Write(output)
}

// Writes a structured JSON error response.
func JSONError(w http.ResponseWriter, err ErrorDetail) {
	JSONResponse(w, err.Status, map[string]string{
		"error":   string(err.Code),
		"message": err.Message,
	})
}

// Writes a structured JSON error response with an override message.
func JSONErrorWithMessage(w http.ResponseWriter, err ErrorDetail, override string) {
	JSONResponse(w, err.Status, map[string]string{
		"error":   string(err.Code),
		"message": override,
	})
}

// Decodes JSON from request with a max size limit.
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

// Attempts to decode the request body into dst and sends an appropriate error response on failure.
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

	// Map custom error responses
	var finalError ErrorDetail
	switch err {
	case ErrRequestTooLarge:
		finalError = Errors.InvalidPayloadSize
	case ErrMalformedJSON, ErrExtraData, ErrEmptyBody:
		finalError = Errors.InvalidPayload
	default:
		finalError = Errors.InternalServerError
	}

	// Log the error
	ctx := r.Context()
	LogWarn(ctx, "Failed to decode JSON request", zap.Error(err))
	sentry.CaptureException(err)

	// Send the error response
	JSONError(w, finalError)
	return false
}
