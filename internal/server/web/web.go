package web

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/clambin/forward-auth/internal/server/web/anticache"
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
	return h
}
