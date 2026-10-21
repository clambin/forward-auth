package validate

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrefixError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantErr require.ErrorAssertionFunc
		want    string
	}{
		{"nil", nil, require.NoError, ""},
		{"assert.AnError", assert.AnError, require.Error, "prefix: assert.AnError general error for testing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := PrefixError("prefix", tt.err)
			tt.wantErr(t, err)
			if err != nil {
				assert.Equal(t, tt.want, err.Error())
			}
		})
	}
}

func TestIsURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  require.ErrorAssertionFunc
	}{
		{"pass", "http://prometheus-alertmanager.monitoring.svc:9093", require.NoError},
		{"no port", "http://prometheus-alertmanager.monitoring.svc", require.NoError},
		{"missing scheme", "prometheus-alertmanager.monitoring.svc:9093", require.Error},
		{"blank", "", require.Error},
		{"invalid url", "localhost", require.Error},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := IsURL(tt.input)
			tt.want(t, err)
		})
	}
}

func TestIsTCPTarget(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  require.ErrorAssertionFunc
	}{
		{"valid tcp target", "127.0.0.1:8080", require.NoError},
		{"port only", ":8080", require.NoError},
		{"blank", "", require.Error},
		{"invalid tcp target", "localhost", require.Error},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := IsTCPTarget(tt.input)
			tt.want(t, err)
		})
	}
}

func TestIsNotZero(t *testing.T) {
	tests := []struct {
		name string
		call func() error
		want require.ErrorAssertionFunc
	}{
		{"string", func() error { return IsNotZero("foo") }, require.NoError},
		{"blank string", func() error { return IsNotZero("") }, require.Error},
		{"duration", func() error { return IsNotZero(time.Second) }, require.NoError},
		{"zero duration", func() error { return IsNotZero(time.Duration(0)) }, require.Error},
		{"int", func() error { return IsNotZero(1) }, require.NoError},
		{"zero int", func() error { return IsNotZero(0) }, require.Error},
		{"float", func() error { return IsNotZero(1.0) }, require.NoError},
		{"float int", func() error { return IsNotZero(0.0) }, require.Error},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want(t, tt.call())
		})
	}
}

func TestIsEnum(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		values []string
		want   require.ErrorAssertionFunc
	}{
		{"valid", "foo", []string{"foo", "bar"}, require.NoError},
		{"invalid", "baz", []string{"foo", "bar"}, require.Error},
		{"blank", "", []string{"foo", "bar"}, require.Error},
		{"blank values", "foo", []string{}, require.Error},
		{"all blank", "", []string{}, require.Error},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want(t, IsEnum(tt.input, tt.values...))
		})
	}
}

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
			tt.want(t, IsMinLength(tt.input, tt.length))
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
			tt.want(t, IsAbsolutePath(tt.input))
		})
	}
}
