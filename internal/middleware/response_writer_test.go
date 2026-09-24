package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"auth-api/internal/entities"
)

func TestResponseWriterMiddleware_CapturesStatus(t *testing.T) {
	var captured int
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw, ok := w.(*entities.ResponseWriter)
		if !ok {
			t.Fatal("expected the wrapped *entities.ResponseWriter")
		}
		if rw.Status != http.StatusOK {
			t.Errorf("default status = %d, want %d before WriteHeader is called", rw.Status, http.StatusOK)
		}
		w.WriteHeader(http.StatusTeapot)
		captured = rw.Status
	})
	handler := ResponseWriterMiddleware(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if captured != http.StatusTeapot {
		t.Errorf("captured status = %d, want %d", captured, http.StatusTeapot)
	}
	if w.Code != http.StatusTeapot {
		t.Errorf("recorder status = %d, want %d", w.Code, http.StatusTeapot)
	}
}
