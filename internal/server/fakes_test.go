package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"sync"
	"time"

	"github.com/clambin/forward-auth/internal/authn"
	"github.com/clambin/forward-auth/internal/authn/cache"
	"github.com/clambin/forward-auth/internal/authn/provider"
)

var _ Authenticator = (*fakeAuthenticator)(nil)

type fakeAuthenticator struct {
	sessions map[string]authn.Session
	states   map[string]string
	codes    map[string]struct{}
	mu       sync.Mutex
}

func (f *fakeAuthenticator) ListSessions(ctx context.Context) (map[string]authn.Session, error) {
	//TODO implement me
	panic("implement me")
}

func (f *fakeAuthenticator) GetSession(ctx context.Context, id string) (authn.Session, error) {
	//TODO implement me
	panic("implement me")
}

func (f *fakeAuthenticator) DeleteSession(ctx context.Context, id string) error {
	//TODO implement me
	panic("implement me")
}

func (f *fakeAuthenticator) Validate(_ context.Context, sessionID string) (*authn.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if session, ok := f.sessions[sessionID]; ok {
		return &session, nil
	}
	return nil, cache.ErrNotFound
}

func (f *fakeAuthenticator) Close(_ context.Context, sessionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sessions, sessionID)
	return nil
}

func (f *fakeAuthenticator) InitiateLogin(_ context.Context, u string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.states == nil {
		f.states = make(map[string]string)
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	state := hex.EncodeToString(b[:])
	f.states[state] = u

	vals := url.Values{
		"state": {state},
		"code":  {"1234"},
	}
	return "https://oicd.example.com/_oauth?" + vals.Encode(), nil
}

func (f *fakeAuthenticator) ConfirmLogin(_ context.Context, state, code string) (*authn.Session, string, string, time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.codes[code]; !ok {
		return nil, "", "", 0, errors.New("invalid code")
	}
	u, ok := f.states[state]
	if !ok {
		return nil, "", "", 0, errors.New("invalid state")
	}
	return &authn.Session{UserInfo: provider.UserInfo{Email: "foo@example.com"}}, "sessionID", u, 0, nil
}

var _ Authorizer = (*fakeAuthorizer)(nil)

type fakeAuthorizer struct {
	allow bool
}

func (f *fakeAuthorizer) Allow(_ *url.URL, _ string) bool {
	return f.allow
}
