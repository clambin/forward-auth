package configuration

import (
	"reflect"
	"slices"
	"strings"
)

// envVars returns the environment variable names declared by env tags
// in the struct type of cfg.
//
// It supports nested structs, pointers to structs, and env prefixes.
// cfg should be a struct or a pointer to a struct.
func envVars(cfg any) []string {
	t := reflect.TypeOf(cfg)
	if t == nil {
		return nil
	}

	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}

	var vars []string
	collectEnvVars(t, "", &vars, make(map[reflect.Type]bool))

	slices.Sort(vars)
	return slices.Compact(vars)
}

func collectEnvVars(
	t reflect.Type,
	prefix string,
	vars *[]string,
	seen map[reflect.Type]bool,
) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || seen[t] {
		return
	}

	seen[t] = true
	defer delete(seen, t)

	for f := range t.Fields() {
		// Only exported fields are considered.
		if f.PkgPath != "" {
			continue
		}

		tag := f.Tag.Get("env")
		name, opts := parseEnvTag(tag)

		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}

		if ft.Kind() == reflect.Struct {
			childPrefix := prefix + name
			if p := opts["prefix"]; p != "" {
				childPrefix = prefix + p
			}

			collectEnvVars(ft, childPrefix, vars, seen)
			continue
		}

		if name != "" {
			*vars = append(*vars, prefix+name)
		}
	}
}

// parseEnvTag extracts the key and comma-separated options from an env tag.
func parseEnvTag(tag string) (string, map[string]string) {
	parts := strings.Split(tag, ",")
	name := strings.TrimSpace(parts[0])
	opts := make(map[string]string)

	for _, part := range parts[1:] {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if found {
			opts[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}

	return name, opts
}
