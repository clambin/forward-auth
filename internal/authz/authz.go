package authz

import (
	"net/url"
	"strings"
	"sync"
)

// Rule represents a single rule for the authorizer.
type Rule struct {
	Domain string   `yaml:"domain"`
	Users  []string `yaml:"users"`
	Groups []string `yaml:"groups"`
}

func (r Rule) match(u *url.URL, user string, groupDefinitions map[string]map[string]struct{}) bool {
	return r.matchDomain(u) && (r.matchUser(user) || r.matchGroup(user, groupDefinitions))
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

func (r Rule) matchGroup(user string, groupDefinitions map[string]map[string]struct{}) bool {
	for _, g := range r.Groups {
		if _, ok := groupDefinitions[user][g]; ok {
			return true
		}
	}
	return false
}

// Group represents a group of users.
type Group struct {
	Name  string   `yaml:"name"`
	Users []string `yaml:"users"`
}

type Authorizer struct {
	init             sync.Once
	Rules            []Rule
	Groups           []Group
	groupDefinitions map[string]map[string]struct{}
}

func (a *Authorizer) GroupsForUser(email string) []string {
	groups := make([]string, 0, len(a.groupDefinitions[email]))
	for group := range a.groupDefinitions[email] {
		groups = append(groups, group)
	}
	return groups
}

func (a *Authorizer) Allow(u *url.URL, user string) bool {
	// on first call, compile all rules
	a.init.Do(a.compile)
	// evaluate all rules. if one matches, allow the request
	for _, rule := range a.Rules {
		if rule.match(u, user, a.groupDefinitions) {
			return true
		}
	}
	return false
}

func (a *Authorizer) compile() {
	// normalize all rules: convert static date to lowercase to optimize case-insensitive comparisons
	for i := range a.Rules {
		a.Rules[i].Domain = strings.ToLower(a.Rules[i].Domain)
		for j := range a.Rules[i].Users {
			a.Rules[i].Users[j] = strings.ToLower(a.Rules[i].Users[j])
		}
		for j := range a.Rules[i].Groups {
			a.Rules[i].Groups[j] = strings.ToLower(a.Rules[i].Groups[j])
		}
	}
	// build group definitions to optimize user-to-group lookups
	// rule needs to know: does this user belong to this group?
	// build a map of users to map of groups
	a.groupDefinitions = make(map[string]map[string]struct{})
	for _, g := range a.Groups {
		g.Name = strings.ToLower(g.Name)
		for _, u := range g.Users {
			u = strings.ToLower(u)
			if _, ok := a.groupDefinitions[u]; !ok {
				a.groupDefinitions[u] = make(map[string]struct{})
			}
			a.groupDefinitions[u][g.Name] = struct{}{}
		}
	}
}
