package configuration

import (
	"fmt"
)

// isMinLength returns an error if value is shorter than min.
func isMinLength(value string, min int) error {
	if len(value) < min {
		return fmt.Errorf("must be at least %d characters long", min)
	}
	return nil
}

// isAbsolutePath returns an error if value is not an absolute path.
func isAbsolutePath(value string) error {
	if value == "" || value[0] != '/' {
		return fmt.Errorf("must be an absolute path")
	}
	return nil
}
