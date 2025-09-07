package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"edibubble-api/config"
	"edibubble-api/internal/utils"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Tunable parameters (safe starting point; TODO adjust after benchmarking on prod hardware).
// Increasing memory is generally more effective than increasing time, but also more expensive on server.
// Find that happy middle :)
const (
	argonTime    uint32 = 2          // iterations
	argonMemory  uint32 = 128 * 1024 // 128 MiB
	argonThreads uint8  = 4
	saltLen             = 16
	keyLen              = 32
)

func randomSalt(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// Hashes the password with the ACTIVE pepper and returns a PHC string like:
// $argon2id$v=19$m=65536,t=1,p=4,pepper=id2$<salt_b64>$<key_b64>
func HashPasswordPHC(password string) (string, error) {
	pm, err := NewStaticPepperManager(config.Loaded.PasswordPeppersRaw, config.Loaded.ActivePepperID)
	if err != nil {
		return "", err
	}
	// Verify the password
	if !utils.IsValidPassword(password) {
		return "", errors.New("invalid password")
	}

	// Get the active pepper config
	pepper, err := pm.ActivePepper()
	if err != nil {
		return "", err
	}
	id := pm.ActiveID()

	// Generate random salt
	salt, err := randomSalt(saltLen)
	if err != nil {
		return "", err
	}

	// Set up the argo setup given the
	key := argon2.IDKey([]byte(password+string(pepper)), salt, argonTime, argonMemory, argonThreads, keyLen)

	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d,pepper=%s$%s$%s",
		argonMemory, argonTime, argonThreads, id,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// Verifies a password against a PHC string. It extracts pepper id from params.
// If the exact pepper isn't found, it can optionally try all peppers (migration mode).
func VerifyPasswordPHC(password, phc string, tryAllIfMissing bool) (bool, error) {
	pm, err := NewStaticPepperManager(config.Loaded.PasswordPeppersRaw, config.Loaded.ActivePepperID)
	if err != nil {
		return false, errors.New("could not create pepper manager")
	}
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("invalid PHC format")
	}

	// params example: "m=65536,t=1,p=4,pepper=id2"
	params := parts[3]
	var mem, timeCost uint32
	var threads uint8
	var pepperID string
	for _, kv := range strings.Split(params, ",") {
		kv = strings.TrimSpace(kv)
		if strings.HasPrefix(kv, "m=") {
			fmt.Sscanf(kv, "m=%d", &mem)
		} else if strings.HasPrefix(kv, "t=") {
			fmt.Sscanf(kv, "t=%d", &timeCost)
		} else if strings.HasPrefix(kv, "p=") {
			fmt.Sscanf(kv, "p=%d", &threads)
		} else if strings.HasPrefix(kv, "pepper=") {
			fmt.Sscanf(kv, "pepper=%s", &pepperID)
		}
	}
	if mem == 0 || timeCost == 0 || threads == 0 {
		return false, errors.New("missing argon params")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decode key: %w", err)
	}

	// Try the indicated pepper first
	if pep, ok := pm.GetPepper(pepperID); ok {
		got := argon2.IDKey([]byte(password+string(pep)), salt, timeCost, mem, threads, uint32(len(want)))
		if subtle.ConstantTimeCompare(got, want) == 1 {
			return true, nil
		}
		return false, nil
	}

	// If pepper id is missing (rotated out), optionally try all peppers
	if tryAllIfMissing {
		for _, pep := range pm.All() {
			got := argon2.IDKey([]byte(password+string(pep)), salt, timeCost, mem, threads, uint32(len(want)))
			if subtle.ConstantTimeCompare(got, want) == 1 {
				return true, nil
			}
		}
	}

	return false, nil
}

// Returns true if hash is using a non-active pepper or old params.
func ShouldRehash(phc string, pm PepperManager) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return true
	}
	params := parts[3]
	var mem, timeCost uint32
	var threads uint8
	var pepperID string
	for _, kv := range strings.Split(params, ",") {
		if strings.HasPrefix(kv, "m=") {
			fmt.Sscanf(kv, "m=%d", &mem)
		}
		if strings.HasPrefix(kv, "t=") {
			fmt.Sscanf(kv, "t=%d", &timeCost)
		}
		if strings.HasPrefix(kv, "p=") {
			fmt.Sscanf(kv, "p=%d", &threads)
		}
		if strings.HasPrefix(kv, "pepper=") {
			fmt.Sscanf(kv, "pepper=%s", &pepperID)
		}
	}
	if mem != argonMemory || timeCost != argonTime || threads != argonThreads {
		return true
	}
	if pepperID != pm.ActiveID() {
		return true
	}
	return false
}
