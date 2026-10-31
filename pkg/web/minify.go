package web

// Dashboard assets are shipped as readable sources (app.js, styles.css,
// compact.css, index.html, theme.js and the lang packs are all hand-edited in
// pkg/web/static/). They are embedded verbatim and served as-is, which leaves a
// lot of whitespace and comments on the wire — roughly 1.1MB raw, frequently
// pulled over the VPN tunnel itself. buildMinifiedFS re-embeds those same
// sources through a whitespace/comment minifier once per server start, so the
// browser receives the smallest reasonable payload while the readable source
// stays the single source of truth. The minified output is served through an
// in-memory fs.FS so the stdlib http.FileServer keeps doing Content-Type,
// Last-Modified/ETag (304) and range handling for free.

import (
	"bytes"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/css"
	"github.com/tdewolff/minify/v2/html"
	"github.com/tdewolff/minify/v2/js"
)

// minifyFS is a read-only in-memory fs.FS holding the minified dashboard assets.
type minifyFS struct {
	files map[string]minifyEntry
}

type minifyEntry struct {
	data    []byte
	modtime time.Time
}

func (m *minifyFS) Open(name string) (fs.File, error) {
	name = strings.TrimPrefix(path.Clean("/"+name), "/")
	e, ok := m.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return &minifyFile{
		Reader:  bytes.NewReader(e.data),
		name:    name,
		size:    int64(len(e.data)),
		modtime: e.modtime,
	}, nil
}

// minifyFile is an fs.File backed by a bytes.Reader with a fixed size/modtime so
// the stdlib http.FileServer derives a stable ETag and Last-Modified (and hence
// 304 responses) from the minified bytes, exactly as it would for a disk file.
type minifyFile struct {
	*bytes.Reader
	name    string
	size    int64
	modtime time.Time
}

func (f *minifyFile) Stat() (fs.FileInfo, error) { return minifyFileInfo{f}, nil }
func (f *minifyFile) Close() error               { return nil }

type minifyFileInfo struct{ f *minifyFile }

func (i minifyFileInfo) Name() string       { return path.Base(i.f.name) }
func (i minifyFileInfo) Size() int64        { return i.f.size }
func (i minifyFileInfo) Mode() fs.FileMode  { return 0o444 }
func (i minifyFileInfo) ModTime() time.Time { return i.f.modtime }
func (i minifyFileInfo) IsDir() bool        { return false }
func (i minifyFileInfo) Sys() any           { return nil }

// buildMinifiedFS walks base (the embedded static dir) and returns a read-only
// FS that serves each text asset minified. Anything that is not HTML/CSS/JS, or
// that the minifier rejects, is served verbatim: a broken minifier must never
// take the dashboard down — it only forfeits the size win for that one file.
func buildMinifiedFS(base fs.FS) (fs.FS, error) {
	m := minify.New()
	// KeepComments: index.html's localePlaceholder is an HTML comment the server
	// replaces with a locale pack per request; stripping it would silently break
	// every non-English locale.
	m.Add("text/html", &html.Minifier{KeepComments: true})
	m.AddFunc("text/css", css.Minify)
	m.AddFunc("application/javascript", js.Minify)

	fsys := &minifyFS{files: map[string]minifyEntry{}}
	modtime := time.Now() // same build time for every file; changes per restart → cache-busting
	err := fs.WalkDir(base, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		raw, err := fs.ReadFile(base, p)
		if err != nil {
			return err
		}
		data := raw
		if mt := minifyMimeType(p); mt != "" {
			if min, merr := m.Bytes(mt, raw); merr == nil && len(min) > 0 {
				data = min
			}
		}
		fsys.files[p] = minifyEntry{data: data, modtime: modtime}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return fsys, nil
}

// minifyMimeType returns the minifiable MIME type for p, or "" when the file
// should be served verbatim (binary, SVG, or any unknown extension).
func minifyMimeType(p string) string {
	switch strings.ToLower(path.Ext(p)) {
	case ".html":
		return "text/html"
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	}
	return ""
}
