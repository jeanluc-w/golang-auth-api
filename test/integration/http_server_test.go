// This file drives real HTTP requests through the actual production stack
// (handlers.NewHandler — the exact routing + middleware wiring cmd/main.go
// uses) via httptest.Server, backed by the shared testcontainers Postgres
// and Redis. Before this file, no test anywhere exercised
// internal/handlers, internal/middleware/{jwt,logging,rate_limit,timeout}.go,
// or internal/server/{server,routes}.go's actual runtime dispatch — every
// other test calls services/auth functions directly, bypassing HTTP,
// routing, and the middleware chain entirely.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"auth-api/config"
	"auth-api/internal/auth"
	"auth-api/internal/entities"
	"auth-api/internal/handlers"
	"auth-api/internal/server"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/ulule/limiter/v3"
	redisstore "github.com/ulule/limiter/v3/drivers/store/redis"
	"go.uber.org/zap"
)

// These mirror the unexported constants in internal/auth/jwt.go
// (jwtIssuer/jwtAudience) — this package can't import them (they're
// unexported), and they're stable protocol constants of this service, not
// values expected to change independently of the tests that assert them.
const (
	testJWTIssuer   = "auth-api"
	testJWTAudience = "auth-app"
)

type testServerOptions struct {
	resendStatus int
}

type testServerOption func(*testServerOptions)

func withFailingResend() testServerOption {
	return func(o *testServerOptions) { o.resendStatus = http.StatusInternalServerError }
}

// newTestServer builds the REAL application handler (handlers.NewHandler)
// wired to the shared testDB/testRedis containers and serves it via
// httptest.Server. Each call gets its own rate-limiter Redis key prefix so
// concurrent test servers never share a rate-limit window, and its own fake
// local Resend backend so no test can ever make a real network call.
func newTestServer(t *testing.T, opts ...testServerOption) *httptest.Server {
	t.Helper()

	options := testServerOptions{resendStatus: http.StatusOK}
	for _, opt := range opts {
		opt(&options)
	}

	fakeResend, _ := newFakeResendClient(t, options.resendStatus)

	store, err := redisstore.NewStoreWithOptions(testRedis, limiter.StoreOptions{
		Prefix:   "rl-" + uuid.NewString(),
		MaxRetry: 1,
	})
	if err != nil {
		t.Fatalf("redisstore.NewStoreWithOptions: %v", err)
	}
	limiterInstance := limiter.New(store, limiter.Rate{Period: time.Second, Limit: 1000})

	svcs := server.NewServices(testDB, testRedis, fakeResend, limiterInstance, zap.NewNop())
	ts := httptest.NewServer(handlers.NewHandler(svcs))
	t.Cleanup(ts.Close)
	return ts
}

// newTestServerWithLimit is like newTestServer but with a caller-chosen,
// tight rate limit — used by the dedicated 429 test.
func newTestServerWithLimit(t *testing.T, limit int64) *httptest.Server {
	t.Helper()
	fakeResend, _ := newFakeResendClient(t, http.StatusOK)

	store, err := redisstore.NewStoreWithOptions(testRedis, limiter.StoreOptions{
		Prefix:   "rl-" + uuid.NewString(),
		MaxRetry: 1,
	})
	if err != nil {
		t.Fatalf("redisstore.NewStoreWithOptions: %v", err)
	}
	limiterInstance := limiter.New(store, limiter.Rate{Period: time.Minute, Limit: limit})

	svcs := server.NewServices(testDB, testRedis, fakeResend, limiterInstance, zap.NewNop())
	ts := httptest.NewServer(handlers.NewHandler(svcs))
	t.Cleanup(ts.Close)
	return ts
}

type httpResponse struct {
	Status int
	Body   map[string]any
	Raw    []byte
	Header http.Header
}

func doRequest(t *testing.T, method, url, authHeader string, body any) httpResponse {
	t.Helper()

	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	// JSONMiddleware requires Content-Type: application/json on every
	// POST/PUT/PATCH regardless of whether there's a body (e.g. logout
	// takes none) — set it whenever body might be nil-but-method-requires-it,
	// not just when there's an actual payload to marshal.
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		req.Header.Set("Content-Type", "application/json")
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http.DefaultClient.Do: %v", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	var parsed map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &parsed) // best-effort; some responses (204) have no body
	}

	return httpResponse{Status: resp.StatusCode, Body: parsed, Raw: raw, Header: resp.Header}
}

// signRawToken mints a JWT directly against config.Loaded's keys, bypassing
// the auth package entirely — used to build tokens with claims production
// code would never construct (expired, wrong audience, etc.) for negative
// test cases.
func signRawToken(t *testing.T, claims entities.JWTClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(config.Loaded.JWTAlgorithm, claims)
	signed, err := tok.SignedString(config.Loaded.JWTPrivateKey)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}

func baseTestClaims(userID, username, role, sessionID string, exp time.Time) entities.JWTClaims {
	now := time.Now()
	return entities.JWTClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    testJWTIssuer,
			Audience:  jwt.ClaimStrings{testJWTAudience},
			ID:        sessionID,
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
		},
	}
}

// loginHTTPUser signs up and logs in a fresh user over real HTTP against
// ts, returning the access token, refresh token, and the session/user IDs
// decoded from the access token.
func loginHTTPUser(t *testing.T, ts *httptest.Server) (accessToken, refreshToken, sessionID, userID string) {
	t.Helper()
	ctx := context.Background()
	email := uniqueEmail(t)
	const password = "correct horse battery staple"

	signUpTestUser(t, ctx, email, "httpuser"+uuid.NewString()[:8], password)

	resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/login", "", map[string]string{
		"email":    email,
		"password": password,
	})
	if resp.Status != http.StatusOK {
		t.Fatalf("login: status = %d, body = %s", resp.Status, resp.Raw)
	}
	accessToken, _ = resp.Body["token"].(string)
	refreshToken, _ = resp.Body["refresh_token"].(string)
	if accessToken == "" || refreshToken == "" {
		t.Fatalf("login response missing tokens: %s", resp.Raw)
	}

	user, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+accessToken)
	if err != nil {
		t.Fatalf("VerifyAndParseJWT: %v", err)
	}
	return accessToken, refreshToken, user.SessionID, user.ID
}

// --- 1. Open routes bypass auth ---

func TestHTTP_OpenRoutes_NoAuthRequired(t *testing.T) {
	ts := newTestServer(t)

	cases := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{"healthcheck", http.MethodGet, "/v1/healthcheck", nil},
		{"login (wrong password)", http.MethodPost, "/auth/v1/login", map[string]string{"email": uniqueEmail(t), "password": "whatever-password"}},
		{"start-email-verification", http.MethodPost, "/auth/v1/start-email-verification", map[string]string{"email": uniqueEmail(t)}},
		{"verify-email (bad code)", http.MethodPost, "/auth/v1/verify-email", map[string]string{"email": uniqueEmail(t), "code": "000000"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := doRequest(t, c.method, ts.URL+c.path, "", c.body)
			if code, _ := resp.Body["error"].(string); code == "unauthorized" {
				t.Errorf("open route %s returned 'unauthorized' (status %d) — should never require auth: %s", c.path, resp.Status, resp.Raw)
			}
		})
	}
}

// --- 2. Protected route rejects bad tokens ---

func TestHTTP_ProtectedRoute_RejectsBadTokens(t *testing.T) {
	ts := newTestServer(t)
	accessToken, _, _, _ := loginHTTPUser(t, ts)

	t.Run("missing header", func(t *testing.T) {
		resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/logout", "", nil)
		if resp.Status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.Status)
		}
	})

	t.Run("malformed header", func(t *testing.T) {
		resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/logout", "garbage-not-bearer", nil)
		if resp.Status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.Status)
		}
	})

	t.Run("tampered signature", func(t *testing.T) {
		tampered := accessToken[:len(accessToken)-4] + "abcd"
		resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/logout", "Bearer "+tampered, nil)
		if resp.Status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.Status)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		expired := signRawToken(t, baseTestClaims("some-user-id", "someone", "user", uuid.NewString(), time.Now().Add(-time.Minute)))
		resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/logout", "Bearer "+expired, nil)
		if resp.Status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.Status)
		}
	})

	t.Run("revoked session", func(t *testing.T) {
		// Use a fresh login so revoking its session doesn't affect other subtests.
		freshAccess, _, freshSessionID, _ := loginHTTPUser(t, ts)
		if err := auth.DeleteSession(context.Background(), freshSessionID, testRedis); err != nil {
			t.Fatalf("DeleteSession: %v", err)
		}
		resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/logout", "Bearer "+freshAccess, nil)
		if resp.Status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 (session was revoked independently of the token's own expiry)", resp.Status)
		}
	})
}

// --- 3. Refresh-token route's special expired-JWT branch ---

func TestHTTP_RefreshTokenRoute_AcceptsExpiredAccessToken(t *testing.T) {
	ts := newTestServer(t)
	_, refreshToken, sessionID, userID := loginHTTPUser(t, ts)

	expired := signRawToken(t, baseTestClaims(userID, "someone", "user", sessionID, time.Now().Add(-time.Minute)))

	resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/refresh-token", "Bearer "+expired, map[string]string{
		"refresh_token": refreshToken,
	})
	if resp.Status != http.StatusOK {
		t.Fatalf("refresh with an expired-but-valid access token: status = %d, body = %s", resp.Status, resp.Raw)
	}
	if resp.Body["token"] == "" || resp.Body["refresh_token"] == "" {
		t.Errorf("expected rotated tokens in response, got %s", resp.Raw)
	}
}

func TestHTTP_RefreshTokenRoute_MissingHeaderRejected(t *testing.T) {
	ts := newTestServer(t)
	_, refreshToken, _, _ := loginHTTPUser(t, ts)

	resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/refresh-token", "", map[string]string{
		"refresh_token": refreshToken,
	})
	if resp.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (refresh route still requires A parseable Bearer token)", resp.Status)
	}
}

func TestHTTP_RefreshTokenRoute_ExpiredButTamperedRejected(t *testing.T) {
	ts := newTestServer(t)
	_, refreshToken, sessionID, userID := loginHTTPUser(t, ts)

	expired := signRawToken(t, baseTestClaims(userID, "someone", "user", sessionID, time.Now().Add(-time.Minute)))
	tampered := expired[:len(expired)-4] + "abcd"

	resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/refresh-token", "Bearer "+tampered, map[string]string{
		"refresh_token": refreshToken,
	})
	if resp.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.Status)
	}
}

// --- 4. Temp-JWT-only route enforcement (cross-check) ---

func TestHTTP_NormalAccessToken_RejectedOnTempJWTRoute(t *testing.T) {
	ts := newTestServer(t)
	accessToken, _, _, _ := loginHTTPUser(t, ts)

	resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/complete-email-join", "Bearer "+accessToken, map[string]string{
		"username":         "shouldnotmatter",
		"password":         "correct horse battery staple",
		"confirm_password": "correct horse battery staple",
	})
	if resp.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (a normal access token's role isn't 'joiner')", resp.Status)
	}
}

func TestHTTP_TemporaryJoinerToken_RejectedOnNormalProtectedRoute(t *testing.T) {
	ts := newTestServer(t)
	ctx := context.Background()
	email := uniqueEmail(t)
	const code = "654321"

	if err := auth.SaveVerificationCode(ctx, testRedis, email, entities.OTPMeta{
		Code:        code,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		MaxAttempts: 5,
	}); err != nil {
		t.Fatalf("SaveVerificationCode: %v", err)
	}

	verifyResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/verify-email", "", map[string]string{
		"email": email,
		"code":  code,
	})
	if verifyResp.Status != http.StatusOK {
		t.Fatalf("verify-email: status = %d, body = %s", verifyResp.Status, verifyResp.Raw)
	}
	joinerToken, _ := verifyResp.Body["token"].(string)
	if joinerToken == "" {
		t.Fatalf("verify-email response missing token: %s", verifyResp.Raw)
	}

	resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/logout", "Bearer "+joinerToken, nil)
	if resp.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (a joiner token must not work as a normal access token)", resp.Status)
	}
}

// --- 5. CORS / security headers on real responses ---

func TestHTTP_SecurityHeaders_PresentOnSuccessAndFailure(t *testing.T) {
	ts := newTestServer(t)

	okResp := doRequest(t, http.MethodGet, ts.URL+"/v1/healthcheck", "", nil)
	failResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/logout", "garbage", nil)

	for _, resp := range []httpResponse{okResp, failResp} {
		for _, h := range []string{"X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security", "Content-Security-Policy"} {
			if resp.Header.Get(h) == "" {
				t.Errorf("status %d response missing header %s", resp.Status, h)
			}
		}
	}
}

func TestHTTP_CORS_AllowedOriginEchoed(t *testing.T) {
	prevLoaded := *config.Loaded
	config.Loaded.Env = "production"
	config.Loaded.AllowedOrigins = []string{"https://app.example.com"}
	t.Cleanup(func() { *config.Loaded = prevLoaded })

	ts := newTestServer(t)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/v1/healthcheck", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Origin", "https://app.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want https://app.example.com", got)
	}
}

func TestHTTP_CORS_DisallowedOriginGetsNoACAO(t *testing.T) {
	prevLoaded := *config.Loaded
	config.Loaded.Env = "production"
	config.Loaded.AllowedOrigins = []string{"https://app.example.com"}
	t.Cleanup(func() { *config.Loaded = prevLoaded })

	ts := newTestServer(t)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/v1/healthcheck", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Origin", "https://evil.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty for a disallowed origin", got)
	}
}

func TestHTTP_OptionsPreflight_ShortCircuits(t *testing.T) {
	ts := newTestServer(t)

	req, err := http.NewRequest(http.MethodOptions, ts.URL+"/auth/v1/login", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) != 0 {
		t.Errorf("expected an empty body for an OPTIONS preflight, got %d bytes", len(raw))
	}
}

// --- 6. Full signup -> login -> refresh -> logout over real HTTP ---

func TestHTTP_FullLifecycle(t *testing.T) {
	ts := newTestServer(t)
	ctx := context.Background()
	email := uniqueEmail(t)
	const code = "112233"
	const password = "correct horse battery staple"

	if err := auth.SaveVerificationCode(ctx, testRedis, email, entities.OTPMeta{
		Code:        code,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		MaxAttempts: 5,
	}); err != nil {
		t.Fatalf("SaveVerificationCode: %v", err)
	}

	verifyResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/verify-email", "", map[string]string{"email": email, "code": code})
	if verifyResp.Status != http.StatusOK {
		t.Fatalf("verify-email: status = %d, body = %s", verifyResp.Status, verifyResp.Raw)
	}
	joinerToken, _ := verifyResp.Body["token"].(string)

	joinResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/complete-email-join", "Bearer "+joinerToken, map[string]string{
		"username":         "lifecycleuser" + uuid.NewString()[:8],
		"password":         password,
		"confirm_password": password,
	})
	if joinResp.Status != http.StatusCreated {
		t.Fatalf("complete-email-join: status = %d, body = %s", joinResp.Status, joinResp.Raw)
	}

	loginResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/login", "", map[string]string{"email": email, "password": password})
	if loginResp.Status != http.StatusOK {
		t.Fatalf("login: status = %d, body = %s", loginResp.Status, loginResp.Raw)
	}
	accessToken, _ := loginResp.Body["token"].(string)
	refreshToken, _ := loginResp.Body["refresh_token"].(string)

	user, err := auth.VerifyAndParseJWT(ctx, testRedis, "Bearer "+accessToken)
	if err != nil {
		t.Fatalf("VerifyAndParseJWT: %v", err)
	}
	expiredAccess := signRawToken(t, baseTestClaims(user.ID, user.Username, user.Role, user.SessionID, time.Now().Add(-time.Minute)))

	refreshResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/refresh-token", "Bearer "+expiredAccess, map[string]string{"refresh_token": refreshToken})
	if refreshResp.Status != http.StatusOK {
		t.Fatalf("refresh-token: status = %d, body = %s", refreshResp.Status, refreshResp.Raw)
	}
	rotatedAccess, _ := refreshResp.Body["token"].(string)
	rotatedRefresh, _ := refreshResp.Body["refresh_token"].(string)

	logoutResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/logout", "Bearer "+rotatedAccess, nil)
	if logoutResp.Status != http.StatusOK {
		t.Fatalf("logout: status = %d, body = %s", logoutResp.Status, logoutResp.Raw)
	}

	// Replaying the pre-rotation refresh token must fail...
	reuseExpiredAccess := signRawToken(t, baseTestClaims(user.ID, user.Username, user.Role, user.SessionID, time.Now().Add(-time.Minute)))
	reuseResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/refresh-token", "Bearer "+reuseExpiredAccess, map[string]string{"refresh_token": refreshToken})
	if reuseResp.Status != http.StatusUnauthorized {
		t.Errorf("replaying the old refresh token: status = %d, want 401", reuseResp.Status)
	}

	// ...and the session should already be dead from the logout above, so
	// even the rotated (never-reused) refresh token no longer works either.
	rotatedResp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/refresh-token", "Bearer "+reuseExpiredAccess, map[string]string{"refresh_token": rotatedRefresh})
	if rotatedResp.Status != http.StatusUnauthorized {
		t.Errorf("refreshing after logout: status = %d, want 401", rotatedResp.Status)
	}
}

// --- 7. 404 / 405 JSON shape ---

// TestHTTP_NotFound uses an AUTHENTICATED request specifically to isolate
// routing behavior from auth — see
// TestHTTP_NotFound_WithoutAuth_ReturnsUnauthorized for what an
// unauthenticated request to the same unknown path actually gets, which is
// a different (and, without a valid token, unreachable) code path.
func TestHTTP_NotFound(t *testing.T) {
	ts := newTestServer(t)
	accessToken, _, _, _ := loginHTTPUser(t, ts)

	resp := doRequest(t, http.MethodGet, ts.URL+"/nonexistent", "Bearer "+accessToken, nil)
	if resp.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.Status)
	}
	if code, _ := resp.Body["error"].(string); code != "route_not_found" {
		t.Errorf("error code = %q, want route_not_found", code)
	}
}

// TestHTTP_NotFound_WithoutAuth_ReturnsUnauthorized documents a real, if
// subtle, consequence of JWTMiddleware running BEFORE routing: it checks
// the request path against server.OpenRoutes/TemporaryJWTRoutes/
// V1_RefreshToken, and anything that doesn't match — including a path with
// NO registered route at all — falls through to requiring a full, valid
// access token. httprouter's own NotFound handler (which returns
// route_not_found, see TestHTTP_NotFound above) is therefore only
// reachable for requests that already carry a valid token; an
// unauthenticated probe of an unknown path gets 401, never 404. Arguably a
// reasonable default (it doesn't let an unauthenticated caller distinguish
// "route doesn't exist" from "route exists but you're not authed"), but
// it's the kind of behavior easy to assume is "obviously 404" without a
// test — hence locking it in here rather than only at TestHTTP_NotFound.
func TestHTTP_NotFound_WithoutAuth_ReturnsUnauthorized(t *testing.T) {
	ts := newTestServer(t)
	resp := doRequest(t, http.MethodGet, ts.URL+"/nonexistent", "", nil)
	if resp.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (see this test's doc comment)", resp.Status)
	}
}

// TestHTTP_MethodNotAllowed documents the ACTUAL current behavior rather
// than an ideal one: httprouter calls router.MethodNotAllowed directly with
// no status pre-set (confirmed from httprouter's source), and this app
// wires that handler to the same utils.Errors.RouteNotFound response used
// for 404s — whose Status field is http.StatusNotFound. So a
// method-not-allowed request currently returns 404, not 405. That may be
// worth a product decision at some point, but changing response semantics
// is outside the scope of adding test coverage, so this test locks in
// today's real behavior rather than the more conventional one.
func TestHTTP_MethodNotAllowed(t *testing.T) {
	ts := newTestServer(t)
	resp := doRequest(t, http.MethodPost, ts.URL+"/v1/healthcheck", "", nil) // healthcheck is GET-only
	if resp.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (see this test's doc comment for why not 405)", resp.Status)
	}
}

// --- 8. Rate limiting (IP-based, the baseline layer) ---

func TestHTTP_RateLimitExceeded(t *testing.T) {
	ts := newTestServerWithLimit(t, 1)

	first := doRequest(t, http.MethodGet, ts.URL+"/v1/healthcheck", "", nil)
	if first.Status != http.StatusOK {
		t.Fatalf("first request: status = %d, want 200", first.Status)
	}

	second := doRequest(t, http.MethodGet, ts.URL+"/v1/healthcheck", "", nil)
	if second.Status != http.StatusTooManyRequests {
		t.Fatalf("second request: status = %d, want 429", second.Status)
	}
	if code, _ := second.Body["error"].(string); code != "too_many_attempts" {
		t.Errorf("error code = %q, want too_many_attempts", code)
	}
}

// --- 9. Request body size limit ---

func TestHTTP_RequestBodyTooLarge(t *testing.T) {
	ts := newTestServer(t)

	oversized := make([]byte, 16*1024) // default limit is 8KB
	for i := range oversized {
		oversized[i] = 'a'
	}
	body := map[string]string{"email": "a@example.com", "password": string(oversized)}

	resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/login", "", body)
	if resp.Status != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.Status)
	}
}

// --- 10. Content-Type enforcement at the full-stack level ---

func TestHTTP_UnsupportedContentType(t *testing.T) {
	ts := newTestServer(t)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/auth/v1/login", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", resp.StatusCode)
	}
}

// --- 11. Handler-layer error forwarding ---

// TestHTTP_StartEmailVerification_ProviderFailureSurfacesAs500 checks the
// HTTP handler's own error-forwarding path (StartEmailVerificationHandler's
// utils.JSONError(w, *err) call), distinct from
// TestStartEmailVerification_EmailProviderFailure in
// start_email_verification_test.go, which checks the same failure at the
// services.StartEmailVerification layer directly.
func TestHTTP_StartEmailVerification_ProviderFailureSurfacesAs500(t *testing.T) {
	ts := newTestServer(t, withFailingResend())

	resp := doRequest(t, http.MethodPost, ts.URL+"/auth/v1/start-email-verification", "", map[string]string{
		"email": uniqueEmail(t),
	})
	if resp.Status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.Status)
	}
	if code, _ := resp.Body["error"].(string); code != "internal_server_error" {
		t.Errorf("error code = %q, want internal_server_error", code)
	}
}
