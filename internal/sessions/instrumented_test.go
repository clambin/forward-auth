package sessions

import (
	"strings"
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/authn/provider"
	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestInstrumentedManager(t *testing.T) {
	sessionManager, _ := New(time.Hour, configuration.StorageConfiguration{})
	_, _ = sessionManager.Add(t.Context(), provider.Identity{Email: "foo@example.com"}, "")

	require.NoError(t, testutil.CollectAndCompare(
		InstrumentedManager{sessionManager},
		strings.NewReader(`
# HELP forward_auth_session_count Number of active sessions
# TYPE forward_auth_session_count gauge
forward_auth_session_count 1
`)))
}
