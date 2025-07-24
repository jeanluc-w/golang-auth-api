package config

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func InitLogger(env string) *zap.Logger {
	// Common encoder config
	encoderCfg := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "", // Remove logging the file reference so it doesn't overwcrowd logs
		MessageKey:     "message",
		StacktraceKey:  "stacktrace",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
	}

	// Choose encoder
	var encoder zapcore.Encoder
	var logLevel zapcore.Level
	if env == "development" {
		encoder = zapcore.NewConsoleEncoder(encoderCfg)
		logLevel = zapcore.DebugLevel
	} else {
		encoder = zapcore.NewJSONEncoder(encoderCfg)
		logLevel = zapcore.InfoLevel
	}

	core := zapcore.NewCore(
		encoder,
		zapcore.AddSync(os.Stdout),
		zap.NewAtomicLevelAt(logLevel),
	)

	logger := zap.New(core)
	return logger
}
