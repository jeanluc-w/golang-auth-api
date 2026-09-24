package entities

import "testing"

// TestContextKeys_AllDistinct guards against a copy-paste collision where
// two unrelated context keys share the same underlying string, which would
// let one silently clobber the other via context.Value lookups.
func TestContextKeys_AllDistinct(t *testing.T) {
	keys := map[string]ContextKey{
		"UserContextKey":                    UserContextKey,
		"RequestContextKey":                 RequestContextKey,
		"StartTimeContextKey":               StartTimeContextKey,
		"LoggerContextKey":                  LoggerContextKey,
		"EmailFromTempJWTContextKey":        EmailFromTempJWTContextKey,
		"JTIFromTempJWTContextKey":          JTIFromTempJWTContextKey,
		"ClientIPContextKey":                ClientIPContextKey,
		"UserAgentContextKey":               UserAgentContextKey,
		"SessionIDFromExpiredJWTContextKey": SessionIDFromExpiredJWTContextKey,
		"UserIDFromExpiredJWTContextKey":    UserIDFromExpiredJWTContextKey,
	}

	seen := make(map[ContextKey]string, len(keys))
	for name, key := range keys {
		if existing, ok := seen[key]; ok {
			t.Errorf("ContextKey %q is shared by both %s and %s", key, existing, name)
		}
		seen[key] = name
	}
}
