package authn

import (
	"strings"
	"testing"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestInstrumentedManager(t *testing.T) {
	authenticator, _ := New(t.Context(), configuration.Configuration{
		Authn: configuration.AuthnConfiguration{Provider: provider.Configuration{Type: "github"}},
	})
	_, _ = authenticator.InitiateLogin(t.Context(), "www.example.com")

	require.NoError(t, testutil.CollectAndCompare(
		InstrumentedAuthenticator{authenticator},
		strings.NewReader(`
# HELP forward_auth_state_count Number of active states
# TYPE forward_auth_state_count gauge
forward_auth_state_count 1
`)))
}
