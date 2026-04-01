package configuration

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoggerConfiguration_Logger(t *testing.T) {
	tests := []struct {
		name string
		cfg  LoggerConfiguration
		want string
	}{
		{"text", LoggerConfiguration{Level: "INFO", Format: "text"}, `level=INFO msg=test`},
		{"json", LoggerConfiguration{Level: "INFO", Format: "json"}, `"level":"INFO","msg":"test"`},
		{"invalid level", LoggerConfiguration{Level: "invalid", Format: "text"}, "invalid log level: invalid. using INFO"},
		{"invalid format", LoggerConfiguration{Level: "INFO", Format: "invalid"}, "invalid log format: invalid. using text"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buff bytes.Buffer
			l := tt.cfg.Logger(&buff)
			l.Info("test")
			assert.Contains(t, buff.String(), tt.want)
		})
	}
}
