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

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: this is to prevent cloudflare from caching the static files while we're in active development.
		/// To be revisited once app development settles down.
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}
