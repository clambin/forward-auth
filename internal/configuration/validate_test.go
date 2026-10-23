package configuration

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsMinLength(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		length int
		want   require.ErrorAssertionFunc
	}{
		{"blank", "", 1, require.Error},
		{"too short", "foo", 4, require.Error},
		{"valid", "foobar", 4, require.NoError},
		{"negative", "foobar", -4, require.NoError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want(t, isMinLength(tt.input, tt.length))
		})
	}
}

func TestIsAbsolutePath(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  require.ErrorAssertionFunc
	}{
		{"blank", "", require.Error},
		{"relative", "foo", require.Error},
		{"absolute", "/foo", require.NoError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want(t, isAbsolutePath(tt.input))
		})
	}
}
