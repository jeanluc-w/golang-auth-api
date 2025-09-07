package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

func HashRefreshToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type PepperManager interface {
	ActiveID() string
	ActivePepper() ([]byte, error)
	GetPepper(id string) ([]byte, bool)
	All() map[string][]byte
}

type StaticPepperManager struct {
	activeID string
	peppers  map[string][]byte // id -> raw bytes
}

func (m *StaticPepperManager) ActiveID() string       { return m.activeID }
func (m *StaticPepperManager) All() map[string][]byte { return m.peppers }
func (m *StaticPepperManager) GetPepper(id string) ([]byte, bool) {
	p, ok := m.peppers[id]
	return p, ok
}
func (m *StaticPepperManager) ActivePepper() ([]byte, error) {
	if p, ok := m.peppers[m.activeID]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("active pepper id %q not found", m.activeID)
}

// Loads peppers from the env and configure the Pepper Manager, used for passwords
func NewStaticPepperManager(raw string, active string) (*StaticPepperManager, error) {
	if raw == "" || active == "" {
		return nil, errors.New("PASSWORD_PEPPERS or ACTIVE_PEPPER_ID missing")
	}
	peppers := make(map[string][]byte)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		s := strings.SplitN(part, ":", 2)
		if len(s) != 2 {
			return nil, fmt.Errorf("invalid pepper entry %q", part)
		}
		id := strings.TrimSpace(s[0])
		b64 := strings.TrimSpace(s[1])
		data, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("decode pepper %q: %w", id, err)
		}
		if len(data) < 16 {
			return nil, fmt.Errorf("pepper %q too short", id)
		}
		peppers[id] = data
	}
	if _, ok := peppers[active]; !ok {
		return nil, fmt.Errorf("active pepper id %q not present", active)
	}
	return &StaticPepperManager{activeID: active, peppers: peppers}, nil
}
