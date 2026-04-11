package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var webFS embed.FS

func New() http.Handler {
	sub, err := fs.Sub(webFS, "static")
	if err != nil {
		panic(err)
	}
	h := http.FileServer(http.FS(sub))

	// this prevents cloudflare from caching the static files while we're in active development.
	if false {
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			h.ServeHTTP(w, r)
		})
	}
	return h
}
