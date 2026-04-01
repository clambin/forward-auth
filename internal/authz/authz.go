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

type Authorizer struct {
	Rules []Rule
}

func New(rules []Rule) (Authorizer, error) {
	for i := range rules {
		rules[i].Domain = strings.ToLower(rules[i].Domain)
		for j := range rules[i].Users {
			rules[i].Users[j] = strings.ToLower(rules[i].Users[j])
		}
	}
	return Authorizer{Rules: rules}, nil
}

func (a Authorizer) Allow(u *url.URL, user string) bool {
	for _, rule := range a.Rules {
		if rule.match(u, user) {
			return true
		}
	}
	return false
}
