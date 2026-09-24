package entities

import (
	"net/http/httptest"
	"testing"
)

func TestResponseWriter_WriteHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &ResponseWriter{ResponseWriter: rec, Status: 200}

	if rw.Status != 200 {
		t.Fatalf("initial Status = %d, want 200", rw.Status)
	}

	rw.WriteHeader(418)

	if rw.Status != 418 {
		t.Errorf("rw.Status = %d, want 418", rw.Status)
	}
	if rec.Code != 418 {
		t.Errorf("underlying recorder code = %d, want 418 (WriteHeader must delegate to the embedded ResponseWriter)", rec.Code)
	}
}
