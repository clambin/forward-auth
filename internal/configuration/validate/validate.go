package validate

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
)

// PrefixError returns an error with the label prefixed to the error message.
// If the error is nil, it returns nil.
func PrefixError(label string, err error) error {
	if err != nil {
		err = fmt.Errorf("%s: %w", label, err)
	}
	return err
}

// IsURL returns an error if value is not a valid URL.
func IsURL(value string) error {
	return errors.Join(
		IsNotZero(value),
		func() error {
			u, err := url.Parse(value)
			if u.Host == "" {
				err = fmt.Errorf("missing scheme?")
			}
			if err != nil {
				return fmt.Errorf("%q is not a valid URL: %w", value, err)
			}
			return nil
		}(),
	)
}

// IsNotZero returns an error if value is the zero value for its type.
func IsNotZero[T comparable](value T) error {
	var zero T
	if value != zero {
		return nil
	}
	var zeroString string
	switch any(value).(type) {
	case string:
		zeroString = "blank"
	default:
		zeroString = "zero"
	}
	return fmt.Errorf("should not be %s", zeroString)
}

// IsMinLength returns an error if value is shorter than min.
func IsMinLength(value string, min int) error {
	if len(value) < min {
		return fmt.Errorf("must be at least %d characters long", min)
	}
	return nil
}

// IsAbsolutePath returns an error if value is not an absolute path.
func IsAbsolutePath(value string) error {
	if value == "" || value[0] != '/' {
		return fmt.Errorf("must be an absolute path")
	}
	return nil
}

// IsTCPTarget returns an error if value is not a valid TCP target.
func IsTCPTarget(value string) error {
	_, _, err := net.SplitHostPort(value)
	return err
}

// IsEnum returns an error if value is not one of the valid values.
func IsEnum(value string, validValues ...string) error {
	if !slices.Contains(validValues, strings.ToLower(value)) {
		return fmt.Errorf("%q is not a valid value", value)
	}
	return nil
}
