package config

import (
	"testing"

	"go.uber.org/zap/zapcore"
)

func TestInitLogger_DevelopmentEnablesDebug(t *testing.T) {
	logger := InitLogger("development")
	if logger == nil {
		t.Fatal("InitLogger returned nil")
	}
	if !logger.Core().Enabled(zapcore.DebugLevel) {
		t.Error("expected debug level to be enabled in development")
	}
}

func TestInitLogger_NonDevelopmentDisablesDebug(t *testing.T) {
	for _, env := range []string{"production", "staging", "test", ""} {
		t.Run(env, func(t *testing.T) {
			logger := InitLogger(env)
			if logger == nil {
				t.Fatal("InitLogger returned nil")
			}
			if logger.Core().Enabled(zapcore.DebugLevel) {
				t.Errorf("expected debug level to be disabled for env=%q", env)
			}
			if !logger.Core().Enabled(zapcore.InfoLevel) {
				t.Errorf("expected info level to remain enabled for env=%q", env)
			}
		})
	}
}
