package anticache

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/clambin/forward-auth/internal/server/web/anticache/testdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAntiCache(t *testing.T) {
	fingerprint, err := fingerprintFS(testdata.FS)
	require.NoError(t, err)
	assetPath := assetRoot + "/" + fingerprint

	h, err := New(testdata.FS, "index.html")
	require.NoError(t, err)

	// validate the index.html file is served and contains the fingerprinted paths
	req, _ := http.NewRequest("GET", "/index.html", nil)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), assetPath)

	// validate index.html is also served from the /
	req, _ = http.NewRequest("GET", "/", nil)
	resp = httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	// validate a fingerprinted asset is served
	req, _ = http.NewRequest("GET", assetPath+"/css/main.css", nil)
	resp = httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	// validate relative paths are redirected to the fingerprinted paths
	req, _ = http.NewRequest("GET", assetPath[1:]+"/css/main.css", nil)
	resp = httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	require.Equal(t, http.StatusTemporaryRedirect, resp.Code)
	assert.Equal(t, assetPath+"/css/main.css", resp.Header().Get("Location"))

	// assets are not available on fixed paths
	req, _ = http.NewRequest("GET", "/css/main.css", nil)
	resp = httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	require.Equal(t, http.StatusNotFound, resp.Code)
}
