package utils

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/getsentry/sentry-go"
	"go.uber.org/zap"
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

var (
	ErrRequestTooLarge = errors.New("request body too large")
	ErrMalformedJSON   = errors.New("malformed JSON")
	ErrEmptyBody       = errors.New("request body is empty")
	ErrExtraData       = errors.New("request body must only contain a single JSON object")
)

// decodeJSONBody decodes JSON from request with a max size limit.
func decodeJSONBody(r *http.Request, dst interface{}, maxBytes int64) error {
	// Limit the size of the request body
	r.Body = http.MaxBytesReader(nil, r.Body, maxBytes)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		switch {
		case strings.Contains(err.Error(), "http: request body too large"):
			return ErrRequestTooLarge
		case errors.Is(err, io.EOF):
			return ErrEmptyBody
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			return ErrMalformedJSON
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

// Public JSON decoder handles decoding the JSON body and sending back appropriate error responses on failure.
// Usage:
// if !utils.MustDecodeJSON(w, r, &body, 4<<10) { 	// 4KB max
//
//		return // error already written to response
//	}
func DecodeJSONHandler(w http.ResponseWriter, r *http.Request, dst interface{}, maxBytes int64) bool {
	err := decodeJSONBody(r, dst, maxBytes)
	if err == nil {
		return true
	}

	var status int
	switch err {
	case ErrRequestTooLarge:
		status = http.StatusRequestEntityTooLarge
	case ErrMalformedJSON, ErrExtraData, ErrEmptyBody:
		status = http.StatusBadRequest
	default:
		status = http.StatusBadRequest
	}

	// Log the error in both Zap and Sentry
	ctx := r.Context()
	LogWarn(ctx, "Failed to decode JSON request",
		zap.String("error", err.Error()),
	)
	sentry.CaptureException(err)

	JSONError(w, status, err.Error())
	return false
}
