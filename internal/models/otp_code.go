package models

import "time"

type OTPMeta struct {
	Code        string    `json:"code"`
	ExpiresAt   time.Time `json:"expires_at"`
	Attempts    int       `json:"attempts"`
	MaxAttempts int       `json:"max_attempts"`
}
