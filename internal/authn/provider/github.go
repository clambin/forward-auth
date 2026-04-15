package provider

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/google/go-github/v84/github"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

var _ Provider = (*gitHubProvider)(nil)

// gitHubProvider authenticates the user using GitHub OAuth2.
type gitHubProvider struct {
	oauth2.Config
	client gitHubClient
}

func newGitHubProvider(redirectURL string, cfg GitHubConfiguration) *gitHubProvider {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"user:email", "read:user"}
	}
	return &gitHubProvider{Config: oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     endpoints.GitHub,
		RedirectURL:  redirectURL,
		Scopes:       cfg.Scopes,
	}}
}

func (o gitHubProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (Identity, error) {
	// use a new gh client, unless testing created a stub
	c := cmp.Or[gitHubClient](
		o.client,
		&realGitHubClient{Client: github.NewClient(o.Config.Client(ctx, token))},
	)

	// get the user
	user, err := c.GetUser(ctx)
	if err != nil {
		return Identity{}, fmt.Errorf("github user: %w", err)
	}

	id := Identity{
		Subject: user.GetLogin(),
		Name:    user.GetName(),
		Email:   user.GetEmail(),
	}

	// if we got an email address, we're done.
	if id.Email != "" {
		return id, nil
	}

	// we didn't get an email address, so we need to get it from the ListEmails API
	//slog.Info("no email address found in user object. getting it from the User Emails API")
	emailAddresses, err := c.GetUserEmails(ctx)
	if err != nil {
		return Identity{}, fmt.Errorf("github email list: %w", err)
	}
	id.Email, err = selectEmailAddress(emailAddresses)
	return id, err
}

func selectEmailAddress(emailAddresses []*github.UserEmail) (string, error) {
	// only consider verified email addresses
	notVerified := func(e *github.UserEmail) bool { return !e.GetVerified() }
	emailAddresses = slices.DeleteFunc(emailAddresses, notVerified)
	if len(emailAddresses) == 0 {
		return "", errors.New("no verified email addresses found")
	}

	// sort the email addresses: move the primary to the top. the others (secondary) are sorted alphabetically.
	slices.SortFunc(emailAddresses, func(a, b *github.UserEmail) int {
		switch {
		case a.GetPrimary():
			return -1
		case b.GetPrimary():
			return 1
		default:
			return cmp.Compare(a.GetEmail(), b.GetEmail())
		}
	})
	return emailAddresses[0].GetEmail(), nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// this improves testability of the gitHub provider: we can stub the API calls without writing a fake server.

type gitHubClient interface {
	GetUser(ctx context.Context) (*github.User, error)
	GetUserEmails(ctx context.Context) ([]*github.UserEmail, error)
}

var _ gitHubClient = (*realGitHubClient)(nil)

type realGitHubClient struct {
	*github.Client
}

func (r realGitHubClient) GetUser(ctx context.Context) (*github.User, error) {
	u, _, err := r.Users.Get(ctx, "")
	return u, err
}

func (r realGitHubClient) GetUserEmails(ctx context.Context) ([]*github.UserEmail, error) {
	emails, _, err := r.Users.ListEmails(ctx, nil)
	return emails, err
}
