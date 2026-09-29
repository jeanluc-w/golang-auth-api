package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
)

// webauthnSessionTTL bounds how long a registration/login ceremony can
// stay in progress before it must be restarted — long enough for a user
// to complete a biometric/PIN prompt, short enough that an abandoned
// ceremony's session data doesn't linger.
const webauthnSessionTTL = 5 * time.Minute

// SaveWebAuthnRegistrationSession stores the *webauthn.SessionData from
// BeginRegistration, scoped to the enrolling user — an authenticated
// action, so there's no separate ceremony token needed (mirrors how MFA
// enrollment codes are keyed by user ID).
func SaveWebAuthnRegistrationSession(ctx context.Context, rdb *redis.Client, userID string, session *webauthn.SessionData) error {
	return saveWebAuthnSession(ctx, rdb, "webauthn_reg:"+userID, session)
}

func GetWebAuthnRegistrationSession(ctx context.Context, rdb *redis.Client, userID string) (*webauthn.SessionData, error) {
	return getWebAuthnSession(ctx, rdb, "webauthn_reg:"+userID)
}

func DeleteWebAuthnRegistrationSession(ctx context.Context, rdb *redis.Client, userID string) error {
	return rdb.Del(ctx, "webauthn_reg:"+userID).Err()
}

// SaveWebAuthnLoginSession stores the *webauthn.SessionData from
// BeginDiscoverableLogin. Unlike registration, login happens before the
// caller has any session, and a discoverable ceremony doesn't identify the
// user until the assertion comes back — so it's scoped to a random
// ceremony ID the client must round-trip, not a user ID.
func SaveWebAuthnLoginSession(ctx context.Context, rdb *redis.Client, ceremonyID string, session *webauthn.SessionData) error {
	return saveWebAuthnSession(ctx, rdb, "webauthn_login:"+ceremonyID, session)
}

func GetWebAuthnLoginSession(ctx context.Context, rdb *redis.Client, ceremonyID string) (*webauthn.SessionData, error) {
	return getWebAuthnSession(ctx, rdb, "webauthn_login:"+ceremonyID)
}

func DeleteWebAuthnLoginSession(ctx context.Context, rdb *redis.Client, ceremonyID string) error {
	return rdb.Del(ctx, "webauthn_login:"+ceremonyID).Err()
}

func saveWebAuthnSession(ctx context.Context, rdb *redis.Client, key string, session *webauthn.SessionData) error {
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal webauthn session: %w", err)
	}
	return rdb.Set(ctx, key, data, webauthnSessionTTL).Err()
}

func getWebAuthnSession(ctx context.Context, rdb *redis.Client, key string) (*webauthn.SessionData, error) {
	val, err := rdb.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal([]byte(val), &session); err != nil {
		return nil, err
	}
	return &session, nil
}
