package models

import "net/http"

// Wrapper for http.ResponseWriter to capture status codes for every response
type ResponseWriter struct {
	http.ResponseWriter
	Status int
}

func (rw *ResponseWriter) WriteHeader(code int) {
	rw.Status = code
	rw.ResponseWriter.WriteHeader(code)
}
