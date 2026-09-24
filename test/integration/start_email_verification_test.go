package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"auth-api/internal/auth"
	"auth-api/internal/entities"
	"auth-api/internal/services"

	"github.com/resend/resend-go/v2"
)

// newFakeResendClient starts a local server standing in for the Resend API
// and returns a *resend.Client redirected at it via the client's exported
// BaseURL field (resend-go builds every request against BaseURL, so this
// needs no production code changes and no real network access). callCount
// is incremented once per request the fake server receives.
func newFakeResendClient(t *testing.T, statusCode int) (client *resend.Client, callCount *atomic.Int32) {
	t.Helper()
	callCount = &atomic.Int32{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if statusCode == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "fake-email-id"})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "simulated failure"})
		}
	}))
	t.Cleanup(server.Close)

	client = resend.NewClient("test-api-key")
	baseURL, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	client.BaseURL = baseURL
	return client, callCount
}

func TestStartEmailVerification_HappyPath(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	fakeResend, callCount := newFakeResendClient(t, http.StatusOK)

	if errDetail := services.StartEmailVerification(ctx, testDB, testRedis, fakeResend, email); errDetail != nil {
		t.Fatalf("StartEmailVerification: %+v", errDetail)
	}

	if callCount.Load() != 1 {
		t.Errorf("fake email server received %d requests, want 1", callCount.Load())
	}

	meta, err := auth.GetVerificationCode(ctx, testRedis, email)
	if err != nil {
		t.Fatalf("GetVerificationCode: %v", err)
	}
	if len(meta.Code) != 6 {
		t.Errorf("stored code %q is not 6 digits", meta.Code)
	}
}

func TestStartEmailVerification_InvalidEmail(t *testing.T) {
	ctx := context.Background()
	fakeResend, callCount := newFakeResendClient(t, http.StatusOK)

	errDetail := services.StartEmailVerification(ctx, testDB, testRedis, fakeResend, "not-an-email")
	if errDetail == nil || errDetail.Code != "invalid_email_format" {
		t.Fatalf("errDetail = %+v, want invalid_email_format", errDetail)
	}
	if callCount.Load() != 0 {
		t.Errorf("expected no email to be sent for an invalid address, got %d calls", callCount.Load())
	}
}

func TestStartEmailVerification_EmailAlreadyTaken(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	signUpTestUser(t, ctx, email, "alreadytakenuser", "correct horse battery staple")

	fakeResend, callCount := newFakeResendClient(t, http.StatusOK)
	errDetail := services.StartEmailVerification(ctx, testDB, testRedis, fakeResend, email)
	if errDetail == nil || errDetail.Code != "email_is_taken" {
		t.Fatalf("errDetail = %+v, want email_is_taken", errDetail)
	}
	if callCount.Load() != 0 {
		t.Errorf("expected no email to be sent for an already-registered address, got %d calls", callCount.Load())
	}
}

func TestStartEmailVerification_TooSoonToRegenerate(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)

	// Seed a code that was "just" created, inside the 1-minute regen window.
	if err := auth.SaveVerificationCode(ctx, testRedis, email, entities.OTPMeta{
		Code:        "111111",
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		MaxAttempts: 5,
	}); err != nil {
		t.Fatalf("SaveVerificationCode: %v", err)
	}

	fakeResend, callCount := newFakeResendClient(t, http.StatusOK)
	errDetail := services.StartEmailVerification(ctx, testDB, testRedis, fakeResend, email)
	if errDetail == nil || errDetail.Code != "too_soon_to_request" {
		t.Fatalf("errDetail = %+v, want too_soon_to_request", errDetail)
	}
	if callCount.Load() != 0 {
		t.Errorf("expected no email to be sent within the regen window, got %d calls", callCount.Load())
	}
}

func TestStartEmailVerification_RegeneratesAfterWindow(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)

	// Seed a code created outside the 1-minute regen window.
	if err := auth.SaveVerificationCode(ctx, testRedis, email, entities.OTPMeta{
		Code:        "222222",
		CreatedAt:   time.Now().Add(-2 * time.Minute),
		ExpiresAt:   time.Now().Add(8 * time.Minute),
		MaxAttempts: 5,
	}); err != nil {
		t.Fatalf("SaveVerificationCode: %v", err)
	}

	fakeResend, callCount := newFakeResendClient(t, http.StatusOK)
	if errDetail := services.StartEmailVerification(ctx, testDB, testRedis, fakeResend, email); errDetail != nil {
		t.Fatalf("StartEmailVerification: %+v", errDetail)
	}
	if callCount.Load() != 1 {
		t.Errorf("expected exactly one email to be sent, got %d calls", callCount.Load())
	}

	meta, err := auth.GetVerificationCode(ctx, testRedis, email)
	if err != nil {
		t.Fatalf("GetVerificationCode: %v", err)
	}
	if meta.Code == "222222" {
		t.Error("expected the old code to be overwritten with a newly generated one")
	}
}

// TestStartEmailVerification_EmailProviderFailure documents an existing
// quirk rather than asserting ideal behavior: the OTP is written to Redis
// BEFORE the email is sent, so a transient email-provider outage still
// consumes the 1-minute regeneration window (the caller gets a 500, but a
// retry within that window is rejected as "too soon" even though no email
// actually went out).
func TestStartEmailVerification_EmailProviderFailure(t *testing.T) {
	ctx := context.Background()
	email := uniqueEmail(t)
	fakeResend, _ := newFakeResendClient(t, http.StatusInternalServerError)

	errDetail := services.StartEmailVerification(ctx, testDB, testRedis, fakeResend, email)
	if errDetail == nil || errDetail.Code != "internal_server_error" {
		t.Fatalf("errDetail = %+v, want internal_server_error", errDetail)
	}

	if _, err := auth.GetVerificationCode(ctx, testRedis, email); err != nil {
		t.Errorf("expected the OTP to still be saved in Redis despite the email send failing, got: %v", err)
	}
}
