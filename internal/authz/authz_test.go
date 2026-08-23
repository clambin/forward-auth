package authz

import (
	"cmp"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthorizer_Allow(t *testing.T) {
	tests := []struct {
		name   string
		rules  []Rule
		groups []Group
		url    *url.URL
		is     assert.BoolAssertionFunc
	}{
		{
			name: "no rules",
			is:   assert.False,
		},
		{
			name:  "wildcard - match",
			rules: []Rule{{Domain: "*.example.com", Users: []string{"foo@example.com"}}},
			is:    assert.True,
		},
		{
			name:  "url case insensitive - match",
			rules: []Rule{{Domain: "*.example.com", Users: []string{"foo@example.com"}}},
			url:   &url.URL{Host: "foo.Example.Com"},
			is:    assert.True,
		},
		{
			name:  "wildcard - mismatch",
			rules: []Rule{{Domain: "*.example.org", Users: []string{"foo@example.org"}}},
			is:    assert.False,
		},
		{
			name:  "user mismatch",
			rules: []Rule{{Domain: "*.example.com", Users: []string{"bar@example.com"}}},
			is:    assert.False,
		},
		{
			name:   "group match",
			rules:  []Rule{{Domain: "*.example.com", Groups: []string{"users"}}},
			groups: []Group{{Name: "users", Users: []string{"foo@example.com"}}},
			is:     assert.True,
		},
		{
			name:   "case-insensitive group match",
			rules:  []Rule{{Domain: "*.example.com", Groups: []string{"users"}}},
			groups: []Group{{Name: "USERS", Users: []string{"foo@example.com"}}},
			is:     assert.True,
		},
		{
			name:   "group mismatch",
			rules:  []Rule{{Domain: "*.example.com", Groups: []string{"users"}}},
			groups: []Group{{Name: "users", Users: []string{"bar@example.com"}}},
			is:     assert.False,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := cmp.Or(tt.url, &url.URL{Host: "foo.example.com"})
			a := Authorizer{Rules: tt.rules, Groups: tt.groups}
			tt.is(t, a.Allow(u, "FOO@example.com"))
		})
	}
}

func BenchmarkAuthorizer(b *testing.B) {
	// Current:
	// BenchmarkAuthorizer-10    	   49477	     22301 ns/op	       0 B/op	       0 allocs/op
	const n = 1000
	users := make([]string, n)
	for i := range n {
		users[i] = fmt.Sprintf("foo-%d@example.com", i)
	}
	rules := make([]Rule, 0, 2*n)
	for i := range n {
		rules = append(rules, Rule{Domain: fmt.Sprintf("*.%d.example.com", i), Users: users})
		rules = append(rules, Rule{Domain: fmt.Sprintf("www.%d.example.com", i), Users: users})
	}
	a := Authorizer{Rules: rules}

	u := &url.URL{Host: fmt.Sprintf("foo.%d.example.com", n-1)}
	user := fmt.Sprintf("foo-%d@example.com", n-1)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if !a.Allow(u, user) {
			b.Fatal("should be allowed")
		}
	}
}

func BenchmarkAuthorizer_Groups(b *testing.B) {
	// Current:
	// BenchmarkAuthorizer_Groups-10    	   56505	     20590 ns/op	       6 B/op	       0 allocs/op
	const n = 1000
	users := make([]string, n)
	for i := range n {
		users[i] = fmt.Sprintf("foo-%d@example.com", i)
	}
	rules := make([]Rule, 0, 2*n)
	for i := range n {
		rules = append(rules, Rule{Domain: fmt.Sprintf("*.%d.example.com", i), Groups: []string{"users"}})
		rules = append(rules, Rule{Domain: fmt.Sprintf("www.%d.example.com", i), Groups: []string{"users"}})
	}
	a := Authorizer{Rules: rules, Groups: []Group{{Name: "users", Users: users}}}

	u := &url.URL{Host: fmt.Sprintf("foo.%d.example.com", n-1)}
	user := fmt.Sprintf("foo-%d@example.com", n-1)

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		if !a.Allow(u, user) {
			b.Fatal("should be allowed")
		}
	}
}
