package anticache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"io"
	"io/fs"
	"net/http"
)

const (
	// assetRoot is the URL path under which the fingerprinted asset tree is mounted.
	assetRoot = "/_assets"
	// immutableCacheControl marks fingerprinted assets as cacheable forever: their URL changes when their content does.
	immutableCacheControl = "public, max-age=31536000, immutable"
)

// New returns a handler serving the embedded web application.
//
// Assets (js, css, ...) are served from /_assets/<fingerprint>/..., where <fingerprint> is a hash over the entire
// embedded tree. Their URLs therefore change whenever any asset changes, which makes them safe to cache forever:
// Cloudflare cannot serve a stale asset, because a new build means new URLs. index.html, which hands out those URLs,
// is the only document served with no-store, and so the only one that must reach the origin on every visit.
//
// index.html is a Go template: it references its assets as {{.AssetPath}}/js/... and is rendered once at startup.
// References inside the js and css files are relative, so they resolve underneath the prefix on their own.
//
// To disable caching altogether rather than key it on content, replace fingerprintFS below with a random value
// generated at startup: everything else works unchanged, at the cost of re-fetching all assets on every page load.
func New(static fs.FS, indexHTML string) (http.Handler, error) {
	// calculate fingerprint from all static assets
	fingerprint, err := fingerprintFS(static)
	if err != nil {
		return nil, err
	}

	// static assets are served from /_assets/<fingerprint>/...
	assetPath := assetRoot + "/" + fingerprint

	// get all asset directories
	assetDirs, err := topLevelDirs(static)
	if err != nil {
		return nil, err
	}

	// create a FileServerFS to serve the static assets
	assets := http.StripPrefix(assetPath, cacheForever(http.FileServerFS(static)))

	// Redirect the fingerprinted assets to the FileServerFS
	mux := http.NewServeMux()
	// Mount each asset directory individually: index.html is served by the handler below, rendered and from memory, so
	// it must not also be reachable through the asset tree — where it would be served unrendered, and cached forever.
	for _, dir := range assetDirs {
		mux.Handle(assetPath+"/"+dir+"/", assets)
	}

	// render index.html once at startup, pointing to the assets at /_assets/<fingerprint>/...
	index, err := renderIndexHTML(static, indexHTML, assetPath)
	if err != nil {
		return nil, err
	}

	// serve index.html from memory
	indexHandler := serveIndex(index)
	mux.Handle("/{$}", indexHandler)
	mux.Handle("/index.html", indexHandler)
	return mux, nil
}

// topLevelDirs returns the names of the directories at the root of fsys, i.e. the asset directories.
func topLevelDirs(fsys fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	dirs := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, entry.Name())
		}
	}
	return dirs, nil
}

// fingerprintFS returns a hash over the names and contents of all files in fsys. fs.WalkDir visits entries in lexical
// order, so the result only depends on the content of the tree, not on how it's walked.
func fingerprintFS(fsys fs.FS) (string, error) {
	hash := sha256.New()
	err := fs.WalkDir(fsys, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		f, err := fsys.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		_, _ = hash.Write([]byte(path))
		_, err = io.Copy(hash, f)
		return err
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil))[:16], nil
}

// renderIndexHTML renders indexHTML, which references its assets as {{.AssetPath}}/js/... , with the fingerprinted path.
// It's rendered once, at startup: the prefix is fixed for the lifetime of the process.
func renderIndexHTML(fsys fs.FS, indexHTML string, assetPath string) ([]byte, error) {
	tmpl, err := template.ParseFS(fsys, indexHTML)
	if err != nil {
		return nil, err
	}
	var body bytes.Buffer
	if err = tmpl.Execute(&body, struct{ AssetPath string }{AssetPath: assetPath}); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func serveIndex(index []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(index)
	})
}

func cacheForever(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", immutableCacheControl)
		next.ServeHTTP(w, r)
	})
}
