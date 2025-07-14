package utils

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

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

	JSONError(w, status, err.Error())
	return false
}
