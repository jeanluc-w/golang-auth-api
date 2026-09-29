package emailer

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"auth-api/config"
)

func TestSendPasswordResetEmail_HappyPath_NoResetURLConfigured(t *testing.T) {
	config.Loaded.EmailFromAddress = "auth <no-reply@mail.auth.com>"
	config.Loaded.PasswordResetURL = ""
	config.Loaded.PasswordResetTTL = 30 * time.Minute

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
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "email-456"})
	})

	id, err := SendPasswordResetEmail("raw-reset-token", "someone@example.com", client)
	if err != nil {
		t.Fatalf("SendPasswordResetEmail: %v", err)
	}
	if id != "email-456" {
		t.Errorf("id = %q, want %q", id, "email-456")
	}

	to, _ := capturedBody["to"].([]any)
	if len(to) != 1 || to[0] != "someone@example.com" {
		t.Errorf("to = %v, want [someone@example.com]", to)
	}
	if capturedBody["subject"] != "Reset your password" {
		t.Errorf("subject = %v, want %q", capturedBody["subject"], "Reset your password")
	}
	if text, _ := capturedBody["text"].(string); !strings.Contains(text, "raw-reset-token") {
		t.Errorf("text body %q does not contain the raw token", text)
	}
	if html, _ := capturedBody["html"].(string); !strings.Contains(html, "raw-reset-token") {
		t.Error("html body does not contain the raw token")
	}
	if html, _ := capturedBody["html"].(string); strings.Contains(html, "<a href=") {
		t.Error("html body should not contain a reset link button when PasswordResetURL is unset")
	}
}

func TestSendPasswordResetEmail_IncludesResetLink_WhenConfigured(t *testing.T) {
	config.Loaded.EmailFromAddress = "auth <no-reply@mail.auth.com>"
	config.Loaded.PasswordResetURL = "https://app.example.com/reset-password"

	var capturedBody map[string]any
	client := newFakeResendServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&capturedBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "email-789"})
	})

	if _, err := SendPasswordResetEmail("raw-reset-token", "someone@example.com", client); err != nil {
		t.Fatalf("SendPasswordResetEmail: %v", err)
	}

	wantLink := "https://app.example.com/reset-password?token=raw-reset-token"
	if text, _ := capturedBody["text"].(string); !strings.Contains(text, wantLink) {
		t.Errorf("text body %q does not contain the reset link %q", text, wantLink)
	}
	if html, _ := capturedBody["html"].(string); !strings.Contains(html, wantLink) {
		t.Error("html body does not contain the reset link")
	}

	config.Loaded.PasswordResetURL = "" // don't leak into other tests in this package
}

func TestSendPasswordResetEmail_APIError(t *testing.T) {
	config.Loaded.EmailFromAddress = "auth <no-reply@mail.auth.com>"
	config.Loaded.PasswordResetURL = ""

	client := newFakeResendServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"boom"}`))
	})

	id, err := SendPasswordResetEmail("raw-reset-token", "someone@example.com", client)
	if err == nil {
		t.Fatal("expected an error from a failing Resend API response")
	}
	if id != "" {
		t.Errorf("id = %q, want empty on error", id)
	}
}
