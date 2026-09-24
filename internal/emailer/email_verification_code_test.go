package emailer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"auth-api/config"

	"github.com/resend/resend-go/v2"
)

func init() {
	if config.Loaded == nil {
		config.Loaded = &config.Config{}
	}
}

// newFakeResendServer starts a local server standing in for the Resend API
// and returns a *resend.Client redirected at it via the client's exported
// BaseURL field — resend-go builds every request against BaseURL, so this
// works with zero production code changes and no real network access.
func newFakeResendServer(t *testing.T, handler http.HandlerFunc) *resend.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client := resend.NewClient("test-api-key")
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	client.BaseURL = baseURL
	return client
}

func TestSendEmailVerificationEmail_HappyPath(t *testing.T) {
	config.Loaded.EmailFromAddress = "auth <no-reply@mail.auth.com>"

	var capturedBody map[string]any
	client := newFakeResendServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/emails" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&capturedBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "email-123"})
	})

	id, err := SendEmailVerificationEmail("654321", "someone@example.com", client)
	if err != nil {
		t.Fatalf("SendEmailVerificationEmail: %v", err)
	}
	if id != "email-123" {
		t.Errorf("id = %q, want %q", id, "email-123")
	}

	to, _ := capturedBody["to"].([]any)
	if len(to) != 1 || to[0] != "someone@example.com" {
		t.Errorf("to = %v, want [someone@example.com]", to)
	}
	if capturedBody["from"] != config.Loaded.EmailFromAddress {
		t.Errorf("from = %v, want %q", capturedBody["from"], config.Loaded.EmailFromAddress)
	}
	if capturedBody["subject"] != "Verification Code" {
		t.Errorf("subject = %v, want %q", capturedBody["subject"], "Verification Code")
	}
	if text, _ := capturedBody["text"].(string); !strings.Contains(text, "654321") {
		t.Errorf("text body %q does not contain the code", text)
	}
	if html, _ := capturedBody["html"].(string); !strings.Contains(html, "654321") {
		t.Errorf("html body does not contain the code")
	}
}

func TestSendEmailVerificationEmail_APIError(t *testing.T) {
	config.Loaded.EmailFromAddress = "auth <no-reply@mail.auth.com>"

	client := newFakeResendServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"boom"}`))
	})

	id, err := SendEmailVerificationEmail("111111", "someone@example.com", client)
	if err == nil {
		t.Fatal("expected an error from a failing Resend API response")
	}
	if id != "" {
		t.Errorf("id = %q, want empty on error", id)
	}
}
