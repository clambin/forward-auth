package provider

import (
	"context"
	"testing"

	"github.com/google/go-github/v84/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitHubProvider(t *testing.T) {
	tests := []struct {
		name   string
		user   *github.User
		emails []*github.UserEmail
		want   Identity
	}{
		{
			name: "user has email address",
			user: &github.User{Login: new("testuser"), Name: new("Test User"), Email: new("testuser@example.com")},
			want: Identity{Subject: "testuser", Name: "Test User", Email: "testuser@example.com"},
		},
		{
			name:   "user has no email address",
			user:   &github.User{Login: new("testuser"), Name: new("Test User")},
			emails: []*github.UserEmail{{Email: new("testuser@example.com"), Primary: new(true), Verified: new(true)}},
			want:   Identity{Subject: "testuser", Name: "Test User", Email: "testuser@example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, _ := New(t.Context(), Configuration{Type: "github"})
			a.(*gitHubProvider).client = &fakeGitHubClient{user: tt.user, emails: tt.emails}

			got, err := a.GetUserInfo(t.Context(), nil)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

}

func Test_selectEmailAddress(t *testing.T) {
	tests := []struct {
		name      string
		addresses []*github.UserEmail
		isErr     require.ErrorAssertionFunc
		want      string
	}{
		{
			name:      "no addresses",
			addresses: []*github.UserEmail{},
			isErr:     require.Error,
		},
		{
			name: "no verified addresses",
			addresses: []*github.UserEmail{
				{Email: new("secondary@example.com"), Primary: new(false), Verified: new(false)},
				{Email: new("primary@example.com"), Primary: new(true), Verified: new(false)},
			},
			isErr: require.Error,
		},
		{
			name: "has primary address",
			addresses: []*github.UserEmail{
				{Email: new("secondary@example.com"), Primary: new(false), Verified: new(true)},
				{Email: new("primary@example.com"), Primary: new(true), Verified: new(true)},
			},
			isErr: require.NoError,
			want:  "primary@example.com",
		},
		{
			name: "has primary address #2",
			addresses: []*github.UserEmail{
				{Email: new("primary@example.com"), Primary: new(true), Verified: new(true)},
				{Email: new("secondary@example.com"), Primary: new(false), Verified: new(true)},
			},
			isErr: require.NoError,
			want:  "primary@example.com",
		},
		{
			name: "no primary address",
			addresses: []*github.UserEmail{
				{Email: new("third@example.com"), Primary: new(false), Verified: new(true)},
				{Email: new("secondary@example.com"), Primary: new(false), Verified: new(true)},
			},
			isErr: require.NoError,
			want:  "secondary@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			address, err := selectEmailAddress(tt.addresses)
			tt.isErr(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, tt.want, address)
		})
	}
}

var _ gitHubClient = (*fakeGitHubClient)(nil)

type fakeGitHubClient struct {
	user   *github.User
	emails []*github.UserEmail
}

func (f *fakeGitHubClient) GetUser(_ context.Context) (*github.User, error) {
	return f.user, nil
}

func (f *fakeGitHubClient) GetUserEmails(_ context.Context) ([]*github.UserEmail, error) {
	return f.emails, nil
}
