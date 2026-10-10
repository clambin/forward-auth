package anticache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"time"
)

type templatedFS struct {
	templatedFiles map[string][]byte
	fileServer     http.Handler
}

func New(fs fs.FS, files ...string) (http.Handler, error) {
	h := templatedFS{
		templatedFiles: make(map[string][]byte),
		fileServer:     http.FileServer(http.FS(fs)),
	}
	// calculate the chksum of all files in the fs
	cksum, err := fingerprintFS(fs)
	if err != nil {
		return templatedFS{}, fmt.Errorf("fingerprinting fs: %w", err)
	}
	// for each template in the paths, generate a version that substitutes the hash
	//   - create a file substituting the path with that checksum
	//   - serve that file specifically
	for _, file := range files {
		content, err := fingerPrintFile(fs, cksum, file)
		if err != nil {
			return templatedFS{}, fmt.Errorf("fingerPrintFile %s: %w", file, err)
		}
		h.templatedFiles["/"+file] = content
	}
	return h, nil
}

func (t templatedFS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// if root, redirect to index.html
	if r.URL.Path == "/" {
		http.Redirect(w, r, "/index.html", http.StatusFound)
		return
	}
	// if the client is requesting a templated file, serve it
	if content, ok := t.templatedFiles[r.URL.Path]; ok {
		_, _ = w.Write(content)
		return
	}
	// serve from the file system
	t.fileServer.ServeHTTP(w, r)
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

// fingerPrintFile renders index.html, which references its assets as {{.AssetPrefix}}/js/... , with the fingerprinted prefix.
// It's rendered once, at startup: the prefix is fixed for the lifetime of the process.
func fingerPrintFile(fsys fs.FS, cksum string, file string) ([]byte, error) {
	tmpl, err := template.ParseFS(fsys, file)
	if err != nil {
		return nil, err
	}
	var body bytes.Buffer
	if err = tmpl.Execute(&body, struct{ Hash string }{Hash: cksum}); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func NoCache(ttl time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d, immutable", int(ttl.Seconds())))
			next.ServeHTTP(w, r)
		})
	}
}
