// HTTP-layer coverage for the admin API surface (internal/handlers/admin*.go,
// registered in router.go via requireRole). admin_test.go already covers the
// service-layer behavior in depth (session revocation, self/admin-target
// refusals, audit attribution); what's missing without this file is proof
// that the actual authorization boundary — requireRole rejecting an
// insufficiently-privileged real request before the handler ever runs — is
// wired correctly end to end, which is exactly what a unit or
// services-layer test can't see.
package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"auth-api/internal/db/postgres"
	"auth-api/internal/services"

	"github.com/google/uuid"
)

// loginHTTPUserWithRole signs up a fresh user, promotes their role directly
// in Postgres (bypassing the admin API — there's no self-service path to
// becoming one), then logs them in over real HTTP so the returned access
// token actually carries that role (role is embedded at login time, not
// looked up per-request).
func loginHTTPUserWithRole(t *testing.T, ts *httptest.Server, role postgres.UserRole) (accessToken, userID string) {
	t.Helper()
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"

	signup := signUpTestUser(t, ctx, email, "httprole"+uuid.NewString()[:8], password)
	promoteUserRole(t, ctx, signup.UserID, role)

	resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/login", "", map[string]string{
		"email": email, "password": password,
	})
	if resp.Status != http.StatusOK {
		t.Fatalf("login: status = %d, body = %s", resp.Status, resp.Raw)
	}
	token, _ := resp.Body["token"].(string)
	if token == "" {
		t.Fatalf("login response missing token: %s", resp.Raw)
	}
	return token, signup.UserID
}

func TestHTTP_Admin_PlainUserForbidden(t *testing.T) {
	ts := newTestServer(t)
	token, _, _, _ := loginHTTPUser(t, ts)

	resp := doRequest(t, http.MethodGet, ts.URL+"/auth/v1/admin/users", "Bearer "+token, nil)
	if resp.Status != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s, want 403", resp.Status, resp.Raw)
	}
	if resp.Body["error"] != "forbidden" {
		t.Errorf("error = %v, want forbidden", resp.Body["error"])
	}
}

func TestHTTP_Admin_NoTokenUnauthorized(t *testing.T) {
	ts := newTestServer(t)

	resp := doRequest(t, http.MethodGet, ts.URL+"/auth/v1/admin/users", "", nil)
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s, want 401", resp.Status, resp.Raw)
	}
}

func TestHTTP_Admin_ModeratorCanListAndGetUsers(t *testing.T) {
	ts := newTestServer(t)
	modToken, _ := loginHTTPUserWithRole(t, ts, postgres.UserRoleModerator)
	_, _, _, targetID := loginHTTPUser(t, ts)

	listResp := doRequest(t, http.MethodGet, ts.URL+"/auth/v1/admin/users?limit=5", "Bearer "+modToken, nil)
	if listResp.Status != http.StatusOK {
		t.Fatalf("list: status = %d, body = %s", listResp.Status, listResp.Raw)
	}
	if _, ok := listResp.Body["users"]; !ok {
		t.Errorf("list response missing 'users' field: %s", listResp.Raw)
	}

	getResp := doRequest(t, http.MethodGet, ts.URL+"/auth/v1/admin/users/"+targetID, "Bearer "+modToken, nil)
	if getResp.Status != http.StatusOK {
		t.Fatalf("get: status = %d, body = %s", getResp.Status, getResp.Raw)
	}
	if getResp.Body["id"] != targetID {
		t.Errorf("get response id = %v, want %s", getResp.Body["id"], targetID)
	}
}

func TestHTTP_Admin_ModeratorForbiddenFromRoleChangeAndDelete(t *testing.T) {
	ts := newTestServer(t)
	modToken, _ := loginHTTPUserWithRole(t, ts, postgres.UserRoleModerator)
	_, _, _, targetID := loginHTTPUser(t, ts)

	roleResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/admin/users/"+targetID+"/role", "Bearer "+modToken, map[string]string{"role": "moderator"})
	if roleResp.Status != http.StatusForbidden {
		t.Errorf("role change: status = %d, body = %s, want 403", roleResp.Status, roleResp.Raw)
	}

	delResp := doRequest(t, http.MethodDelete, ts.URL+"/auth/v1/admin/users/"+targetID, "Bearer "+modToken, nil)
	if delResp.Status != http.StatusForbidden {
		t.Errorf("delete: status = %d, body = %s, want 403", delResp.Status, delResp.Raw)
	}
}

func TestHTTP_Admin_AdminCanChangeRoleAndBan(t *testing.T) {
	ts := newTestServer(t)
	adminToken, _ := loginHTTPUserWithRole(t, ts, postgres.UserRoleAdmin)
	_, _, _, targetID := loginHTTPUser(t, ts)

	roleResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/admin/users/"+targetID+"/role", "Bearer "+adminToken, map[string]string{"role": "moderator"})
	if roleResp.Status != http.StatusOK {
		t.Fatalf("role change: status = %d, body = %s", roleResp.Status, roleResp.Raw)
	}

	banResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/admin/users/"+targetID+"/ban", "Bearer "+adminToken, map[string]string{"reason": "http test"})
	if banResp.Status != http.StatusOK {
		t.Fatalf("ban: status = %d, body = %s", banResp.Status, banResp.Raw)
	}

	got, errDetail := services.GetUser(context.Background(), testDB, targetID)
	if errDetail != nil {
		t.Fatalf("GetUser: %+v", errDetail)
	}
	if got.Role != "moderator" {
		t.Errorf("role = %q, want moderator", got.Role)
	}
	if got.Status != "banned" {
		t.Errorf("status = %q, want banned", got.Status)
	}
}

func TestHTTP_Admin_UnknownUserID_NotFound(t *testing.T) {
	ts := newTestServer(t)
	adminToken, _ := loginHTTPUserWithRole(t, ts, postgres.UserRoleAdmin)

	resp := doRequest(t, http.MethodGet, ts.URL+"/auth/v1/admin/users/"+uuid.NewString(), "Bearer "+adminToken, nil)
	if resp.Status != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s, want 404", resp.Status, resp.Raw)
	}
}

// TestHTTP_Admin_AuditLogReflectsActor is a light end-to-end confirmation
// that the actor-attribution wiring proven at the service level in
// admin_test.go actually holds when the request comes in over real HTTP
// through requireRole rather than a direct service call.
func TestHTTP_Admin_AuditLogReflectsActor(t *testing.T) {
	ts := newTestServer(t)
	adminToken, adminID := loginHTTPUserWithRole(t, ts, postgres.UserRoleAdmin)
	_, _, _, targetID := loginHTTPUser(t, ts)

	resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/admin/users/"+targetID+"/force-logout", "Bearer "+adminToken, map[string]string{"reason": "http audit check"})
	if resp.Status != http.StatusOK {
		t.Fatalf("force-logout: status = %d, body = %s", resp.Status, resp.Raw)
	}

	logsResp := doRequest(t, http.MethodGet, fmt.Sprintf("%s/auth/v1/admin/audit-logs?target_user_id=%s", ts.URL, targetID), "Bearer "+adminToken, nil)
	if logsResp.Status != http.StatusOK {
		t.Fatalf("audit-logs: status = %d, body = %s", logsResp.Status, logsResp.Raw)
	}
	entries, _ := logsResp.Body["entries"].([]any)
	found := false
	for _, e := range entries {
		entry, _ := e.(map[string]any)
		if entry["action"] == "admin_note" && entry["actor_id"] == adminID {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an admin_note audit entry attributed to %s, got %s", adminID, logsResp.Raw)
	}
}
