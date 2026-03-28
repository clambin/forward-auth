package authz

import (
	"net/url"
	"strings"
)

type Rule struct {
	Domain string   `yaml:"domain"`
	Users  []string `yaml:"users"`
}

func (r Rule) match(u *url.URL, user string) bool {
	return r.matchDomain(u) && r.matchUser(user)
}

func (r Rule) matchDomain(u *url.URL) bool {
	if !strings.HasPrefix(r.Domain, "*.") {
		return strings.EqualFold(u.Host, r.Domain)
	}
	return strings.HasSuffix(strings.ToLower(u.Host), r.Domain[1:])
}

func (r Rule) matchUser(user string) bool {
	for _, u := range r.Users {
		if strings.EqualFold(u, user) {
			return true
		}
	}
	return false
}

type Configuration struct {
	Rules []Rule `yaml:"rules"`
}

type Authorizer struct {
	Rules []Rule
}

func New(configuration Configuration) (Authorizer, error) {
	for i := range configuration.Rules {
		configuration.Rules[i].Domain = strings.ToLower(configuration.Rules[i].Domain)
		for j := range configuration.Rules[i].Users {
			configuration.Rules[i].Users[j] = strings.ToLower(configuration.Rules[i].Users[j])
		}
	}
	return Authorizer(configuration), nil
}

func (a Authorizer) Allow(u *url.URL, user string) bool {
	for _, rule := range a.Rules {
		if rule.match(u, user) {
			return true
		}
	}
	return false
}
