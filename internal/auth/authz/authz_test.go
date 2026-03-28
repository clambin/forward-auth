package authz

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthorizer(t *testing.T) {
	a, _ := New(Configuration{Rules: []Rule{
		{
			Domain: "*.example.com",
			Users:  []string{"foo@example.com", "bar@example.com"},
		},
		{
			Domain: "www.example.org",
			Users:  []string{"foo@example.org", "bar@example.org"},
		},
	}})
	tests := []struct {
		name string
		url  *url.URL
		user string
		is   assert.BoolAssertionFunc
	}{
		{"wildcard - match", &url.URL{Host: "foo.example.com"}, "foo@example.com", assert.True},
		{"wildcard - user mismatch", &url.URL{Host: "foo.example.com"}, "snafu@example.com", assert.False},
		{"wildcard - domain mismatch", &url.URL{Host: "foo.example.org"}, "foo@example.com", assert.False},
		{"fqdn - match", &url.URL{Host: "www.example.org"}, "bar@example.org", assert.True},
		{"fqdn - user mismatch", &url.URL{Host: "www.example.org"}, "snafu@example.org", assert.False},
		{"fqdn - domain mismatch", &url.URL{Host: "www.example.net"}, "bar@example.org", assert.False},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.is(t, a.Allow(tt.url, tt.user))
		})
	}
}

// Current:
// BenchmarkAuthorizer-10    	   44482	     26621 ns/op	       0 B/op	       0 allocs/op
func BenchmarkAuthorizer(b *testing.B) {
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
	a, _ := New(Configuration{Rules: rules})

	u := &url.URL{Host: fmt.Sprintf("foo.%d.example.com", n-1)}
	user := fmt.Sprintf("foo-%d@example.com", n-1)

	b.ReportAllocs()
	for b.Loop() {
		if !a.Allow(u, user) {
			b.Fatal("should be allowed")
		}
	}
}
