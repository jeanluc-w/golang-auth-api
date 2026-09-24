package utils

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"auth-api/config"
)

func init() {
	// JSONResponse/JSONError read config.Loaded.Env; set a safe default so
	// these tests don't depend on test ordering across the package.
	if config.Loaded == nil {
		config.Loaded = &config.Config{Env: "test"}
	}
}

type decodeTarget struct {
	Name string `json:"name"`
}

func TestDecodeJSONHandler_Valid(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"alice"}`))
	w := httptest.NewRecorder()

	var dst decodeTarget
	if !DecodeJSONHandler(w, req, &dst) {
		t.Fatalf("expected success, got response %d: %s", w.Code, w.Body.String())
	}
	if dst.Name != "alice" {
		t.Errorf("dst.Name = %q, want %q", dst.Name, "alice")
	}
}

func TestDecodeJSONHandler_EmptyBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(``))
	w := httptest.NewRecorder()

	var dst decodeTarget
	if DecodeJSONHandler(w, req, &dst) {
		t.Fatal("expected failure for empty body")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestDecodeJSONHandler_MalformedJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{not json`))
	w := httptest.NewRecorder()

	var dst decodeTarget
	if DecodeJSONHandler(w, req, &dst) {
		t.Fatal("expected failure for malformed JSON")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestDecodeJSONHandler_UnknownField(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"alice","surprise":true}`))
	w := httptest.NewRecorder()

	var dst decodeTarget
	if DecodeJSONHandler(w, req, &dst) {
		t.Fatal("expected failure for unknown field")
	}
}

func TestDecodeJSONHandler_ExtraTrailingData(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"alice"}{"name":"bob"}`))
	w := httptest.NewRecorder()

	var dst decodeTarget
	if DecodeJSONHandler(w, req, &dst) {
		t.Fatal("expected failure for trailing extra JSON data")
	}
}

func TestDecodeJSONHandler_TooLarge(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	w := httptest.NewRecorder()

	var dst decodeTarget
	if DecodeJSONHandler(w, req, &dst, 16) {
		t.Fatal("expected failure for body exceeding maxBytes")
	}
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d", w.Code, http.StatusRequestEntityTooLarge)
	}
}
