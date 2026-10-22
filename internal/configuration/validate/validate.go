package validate

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"
)

// IsValid calls IsValid() on each field of value that is a struct implementing `IsValid() error`,
// and returns all errors joined into a single error. `value` must be a struct.
// Struct fields that don't implement IsValid() are traversed recursively.
// Struct fields that implement `IsValid()` are evaluated but not traversed recursively.
// Each error is prefixed with the field's yaml tag name or, if it has none, the field's name, in lowercase.
func IsValid(value any) error {
	v := reflect.ValueOf(value)
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("%T is not a struct", value)
	}
	var errs error
	for i := range v.NumField() {
		field := v.Field(i)
		if field.Kind() != reflect.Struct || !field.CanInterface() {
			continue
		}
		var err error
		if validator, ok := field.Interface().(interface{ IsValid() error }); ok {
			err = validator.IsValid()
		} else {
			err = IsValid(field.Interface())
		}
		errs = errors.Join(errs, PrefixError(fieldLabel(v.Type().Field(i)), err))
	}
	return errs
}

// fieldLabel returns the field's yaml tag name, or the field's name if it has no yaml tag name.
func fieldLabel(field reflect.StructField) string {
	if name, _, _ := strings.Cut(field.Tag.Get("yaml"), ","); name != "" && name != "-" {
		return name
	}
	return strings.ToLower(field.Name)
}

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
			if err != nil {
				return fmt.Errorf("%q is not a valid URL: %w", value, err)
			}
			if u.Host == "" {
				err = fmt.Errorf("missing scheme")
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
	host, _, err := net.SplitHostPort(value)
	if host == "" {
		return fmt.Errorf("must have a valid target host")
	}
	return err
}

// IsTCPListener returns an error if value is not a valid TCP listener.
func IsTCPListener(value string) error {
	_, _, err := net.SplitHostPort(value)
	return err
}

// IsEnum returns an error if value is not one of the valid values.
// Match is case-insensitive.
func IsEnum(value string, validValues ...string) error {
	for _, validValue := range validValues {
		if strings.EqualFold(validValue, value) {
			return nil
		}
	}
	return fmt.Errorf("%q is not a valid value", value)
}
