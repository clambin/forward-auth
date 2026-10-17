package authn

import (
	"testing"
	"time"

	"github.com/clambin/forward-auth/internal/configuration"
	"github.com/clambin/forward-auth/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStates(t *testing.T) {
	endpoint := testutils.RedisTestContainer(t)

	tests := []struct {
		name    string
		cfg     configuration.StorageConfiguration
		wantErr require.ErrorAssertionFunc
	}{
		{"local", configuration.StorageConfiguration{Type: "local"}, require.NoError},
		{"redis", configuration.StorageConfiguration{Type: "redis", Redis: configuration.StorageRedisConfiguration{Addr: endpoint}}, require.NoError},
		{"invalid", configuration.StorageConfiguration{Type: "invalid"}, require.Error},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			store, err := newStates(5*time.Minute, tt.cfg)
			tt.wantErr(t, err)

			if err != nil {
				return
			}

			// add a record
			state, err := store.Allocate(ctx, "test")
			require.NoError(t, err)
			assert.NotEmpty(t, state)

			// check that the record was added
			count, err := store.Len(ctx)
			require.NoError(t, err)
			assert.Equal(t, 1, count)

			// retrieve the record
			value, err := store.Validate(ctx, state)
			require.NoError(t, err)
			assert.Equal(t, "test", value)

			// check that the state has been removed
			_, err = store.Validate(ctx, state)
			require.Error(t, err)
			count, err = store.Len(ctx)
			require.NoError(t, err)
			assert.Equal(t, 0, count)
		})
	}
}
