package web

import (
	"embed"
	"io/fs"
	"net/http"
	"time"

	"github.com/clambin/forward-auth/anticache"
)

//go:embed static
var webFS embed.FS

func New() http.Handler {
	sub, err := fs.Sub(webFS, "static")
	if err != nil {
		panic(err)
	}

	h, err := anticache.New(sub, "index.html")
	if err != nil {
		panic(err)
	}
	return anticache.NoCache(365 * 24 * time.Hour)(h)
}
