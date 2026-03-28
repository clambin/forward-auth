package auth

import (
	"time"

	"github.com/clambin/forward-auth/internal/auth/authn"
	"github.com/clambin/forward-auth/internal/auth/authz"
	"github.com/clambin/forward-auth/internal/auth/cache"
)

type Configuration struct {
	CookieName string              `yaml:"cookie_name"`
	Authn      authn.Configuration `yaml:"authn"`
	Storage    cache.Configuration `yaml:"storage"`
	Authz      authz.Configuration `yaml:"authz"`
	SessionTTL time.Duration       `yaml:"session_ttl"`
	StateTTL   time.Duration       `yaml:"state_ttl"`
}

var DefaultConfiguration = Configuration{
	CookieName: "forward-auth-session",
	Authn:      authn.Configuration{},
	Storage: cache.Configuration{
		Type: "local",
	},
	Authz:      authz.Configuration{},
	SessionTTL: 24 * time.Hour,
	StateTTL:   5 * time.Minute,
}
