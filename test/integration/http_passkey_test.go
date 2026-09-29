// HTTP-layer coverage for the passkey endpoints. As with
// passkey_test.go, this does NOT simulate a real signed WebAuthn
// ceremony response — see that file's package doc for why. What's
// covered here instead: routing/JSON wiring for the endpoints that don't
// need one (begin, and management), and that every passkey endpoint
// degrades to a clean "not configured" response over real HTTP when
// WEBAUTHN_RP_ID isn't set, which is the server's actual default and the
// one every other test in this package runs under.
package integration

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

func testHTTPWebAuthn(t *testing.T) *webauthn.WebAuthn {
	t.Helper()
	w, err := webauthn.New(&webauthn.Config{
		RPID:          "example.com",
		RPDisplayName: "auth-api test",
		RPOrigins:     []string{"https://example.com"},
	})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	return w
}

func TestHTTP_Passkey_NotConfigured_AllEndpointsDegradeCleanly(t *testing.T) {
	ts := newTestServer(t) // no withWebAuthn — WebAuthn is nil, the production default
	token, _, _, _ := loginHTTPUser(t, ts)

	cases := []struct {
		name, method, path string
		auth               string
	}{
		{"register/begin", http.MethodPost, "/auth/v1/passkey/register/begin", "Bearer " + token},
		{"register/finish", http.MethodPost, "/auth/v1/passkey/register/finish", "Bearer " + token},
		{"login/begin", http.MethodPost, "/auth/v1/passkey/login/begin", ""},
		{"login/finish", http.MethodPost, "/auth/v1/passkey/login/finish?ceremony_id=x", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := doRequest(t, c.method, ts.URL+c.path, c.auth, nil)
			if resp.Status != http.StatusServiceUnavailable {
				t.Errorf("status = %d, body = %s, want 503", resp.Status, resp.Raw)
			}
			if resp.Body["error"] != "passkey_not_configured" {
				t.Errorf("error = %v, want passkey_not_configured", resp.Body["error"])
			}
		})
	}
}

func TestHTTP_Passkey_RegisterBegin_RequiresAuth(t *testing.T) {
	ts := newTestServer(t, withWebAuthn(testHTTPWebAuthn(t)))

	resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/passkey/register/begin", "", nil)
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s, want 401", resp.Status, resp.Raw)
	}
}

func TestHTTP_Passkey_RegisterBegin_ReturnsCreationOptions(t *testing.T) {
	ts := newTestServer(t, withWebAuthn(testHTTPWebAuthn(t)))
	token, _, _, _ := loginHTTPUser(t, ts)

	resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/passkey/register/begin", "Bearer "+token, nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.Status, resp.Raw)
	}
	respField, ok := resp.Body["response"].(map[string]any)
	if !ok {
		t.Fatalf("expected a 'response' object in the creation options: %s", resp.Raw)
	}
	if respField["challenge"] == nil || respField["challenge"] == "" {
		t.Errorf("expected a non-empty challenge: %s", resp.Raw)
	}
	rp, ok := respField["rp"].(map[string]any)
	if !ok || rp["id"] != "example.com" {
		t.Errorf("expected rp.id = example.com: %s", resp.Raw)
	}
}

func TestHTTP_Passkey_LoginBegin_ReturnsCeremonyIDAndOptions(t *testing.T) {
	ts := newTestServer(t, withWebAuthn(testHTTPWebAuthn(t)))

	resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/passkey/login/begin", "", nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.Status, resp.Raw)
	}
	if resp.Body["ceremony_id"] == nil || resp.Body["ceremony_id"] == "" {
		t.Errorf("expected a non-empty ceremony_id: %s", resp.Raw)
	}
	if _, ok := resp.Body["options"].(map[string]any); !ok {
		t.Errorf("expected an 'options' object: %s", resp.Raw)
	}
}

func TestHTTP_Passkey_ManagementLifecycle(t *testing.T) {
	ts := newTestServer(t)
	token, _, _, userID := loginHTTPUser(t, ts)

	passkeyID := seedPasskey(t, context.Background(), userID, "HTTP Test Key")

	listResp := doRequest(t, http.MethodGet, ts.URL+"/auth/v1/passkey/credentials", "Bearer "+token, nil)
	if listResp.Status != http.StatusOK {
		t.Fatalf("list: status = %d, body = %s", listResp.Status, listResp.Raw)
	}
	passkeys, _ := listResp.Body["passkeys"].([]any)
	if len(passkeys) != 1 {
		t.Fatalf("passkeys = %v, want exactly one", passkeys)
	}

	renameResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/passkey/credentials/"+passkeyID+"/rename", "Bearer "+token, map[string]string{"name": "Renamed via HTTP"})
	if renameResp.Status != http.StatusOK {
		t.Fatalf("rename: status = %d, body = %s", renameResp.Status, renameResp.Raw)
	}

	// A stranger can't rename or delete it.
	otherToken, _, _, _ := loginHTTPUser(t, ts)
	strangerResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/passkey/credentials/"+passkeyID+"/rename", "Bearer "+otherToken, map[string]string{"name": "Hijacked"})
	if strangerResp.Status == http.StatusOK {
		t.Error("expected another user renaming this passkey over HTTP to be rejected")
	}

	deleteResp := doRequest(t, http.MethodDelete, ts.URL+"/auth/v1/passkey/credentials/"+passkeyID, "Bearer "+token, map[string]string{"current_password": "correct horse battery staple"})
	if deleteResp.Status != http.StatusOK {
		t.Fatalf("delete: status = %d, body = %s", deleteResp.Status, deleteResp.Raw)
	}
}
