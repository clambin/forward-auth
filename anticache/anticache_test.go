package anticache

import (
	"embed"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

//go:embed testdata
var testdata embed.FS

func TestNew(t *testing.T) {
	subFS, err := fs.Sub(testdata, "testdata")
	if err != nil {
		t.Fatalf("missing testdata: %v", err)
	}
	h, err := New(subFS, "index.html")
	if err != nil {
		t.Fatalf("failed to create anticache: %v", err)
	}
	h = NoCache(365 * 24 * time.Hour)(h)

	cksum, err := fingerprintFS(subFS)
	if err != nil {
		t.Fatalf("failed to fingerprint testdata: %v", err)
	}

	req, _ := http.NewRequest("GET", "/index.html", nil)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected response code: %d", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "Title "+cksum) {
		t.Fatalf("unexpected response body: %s", resp.Body.String())
	}

	req, _ = http.NewRequest("GET", "/foo.txt", nil)
	resp = httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected response code: %d", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "Foo!") {
		t.Fatalf("unexpected response body: %s", resp.Body.String())
	}

	rootDirect := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				r.URL.Path = "/index.html"
			}
			next.ServeHTTP(w, r)
		})
	}

	req, _ = http.NewRequest("GET", "/", nil)
	resp = httptest.NewRecorder()
	rootDirect(h).ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected response code: %d", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "Title "+cksum) {
		t.Fatalf("unexpected response body: %s", resp.Body.String())
	}
}
