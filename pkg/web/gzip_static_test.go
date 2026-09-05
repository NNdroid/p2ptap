package web

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func newGzipTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	fsys := fstest.MapFS{
		"app.js":        &fstest.MapFile{Data: []byte(strings.Repeat("console.log('p2ptap');\n", 1000))},
		"styles.css":    &fstest.MapFile{Data: []byte(strings.Repeat("body{margin:0}\n", 500))},
		"index.html":    &fstest.MapFile{Data: []byte("<html><body>p2ptap</body></html>")},
		"icon.bin":      &fstest.MapFile{Data: []byte{0x00, 0x01, 0x02, 0x03}},
		"favicon.svg":   &fstest.MapFile{Data: []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)},
	}
	return httptest.NewServer(gzipStaticMiddleware(http.FileServer(http.FS(fsys))))
}

func TestGzipStaticCompressesCompressibleTypes(t *testing.T) {
	ts := newGzipTestServer(t)
	defer ts.Close()

	// JS asset: must be gzipped when the client accepts gzip.
	req, _ := http.NewRequest("GET", ts.URL+"/app.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET app.js: %v", err)
	}
	defer resp.Body.Close()
	if enc := resp.Header.Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", enc)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Fatalf("Content-Type = %q, want javascript", ct)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("body is not valid gzip: %v", err)
	}
	body, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gzip read: %v", err)
	}
	if !strings.Contains(string(body), "p2ptap") {
		t.Fatalf("decompressed body does not match original asset")
	}
}

func TestGzipStaticPassthrough(t *testing.T) {
	ts := newGzipTestServer(t)
	defer ts.Close()

	// Without Accept-Encoding: identity.
	resp, err := http.Get(ts.URL + "/app.js")
	if err != nil {
		t.Fatalf("GET app.js: %v", err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Encoding") == "gzip" {
		t.Fatalf("identity request must not be gzipped")
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "p2ptap") {
		t.Fatalf("identity body mismatch")
	}

	// Binary content type with gzip accepted: passthrough.
	req, _ := http.NewRequest("GET", ts.URL+"/icon.bin", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET icon.bin: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.Header.Get("Content-Encoding") == "gzip" {
		t.Fatalf("binary asset must not be gzipped")
	}
	if b, _ := io.ReadAll(resp2.Body); len(b) != 4 || b[0] != 0x00 {
		t.Fatalf("binary asset corrupted: %v", b)
	}
}
