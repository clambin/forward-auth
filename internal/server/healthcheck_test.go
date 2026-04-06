package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func TestHealthCheck(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"no error", nil, http.StatusOK},
		{"redis error", assert.AnError, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := healthCheckHandler(
				fakeRedisClient{err: tt.err},
				slog.New(slog.DiscardHandler),
			)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			resp := httptest.NewRecorder()
			h.ServeHTTP(resp, req)
			assert.Equal(t, tt.want, resp.Code)
		})
	}
}

var _ RedisClient = fakeRedisClient{}

type fakeRedisClient struct{ err error }

func (f fakeRedisClient) Ping(ctx context.Context) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(ctx)
	cmd.SetErr(f.err)
	return cmd
}
