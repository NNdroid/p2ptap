package web

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testStaticSub(t *testing.T) fs.FS {
	t.Helper()
	base, err := fs.Sub(staticFS, "static")
	if err != nil {
		t.Fatal(err)
	}
	return base
}

// TestBuildMinifiedFS keeps the minification honest: every asset stays served,
// the readable source is actually shrunk, and nothing the browser relies on
// (the locale placeholder comment, the global identifiers data-onclick handlers
// resolve against) is dropped by the minifier.
func TestBuildMinifiedFS(t *testing.T) {
	base := testStaticSub(t)
	minFS, err := buildMinifiedFS(base)
	if err != nil {
		t.Fatal(err)
	}

	// Every shipped asset is still served (English has no pack: it is inlined in
	// app.js as the fallback dictionary).
	for _, p := range []string{
		"index.html", "app.js", "styles.css", "compact.css", "theme.js",
		"lang/de.js", "lang/es.js", "lang/fr.js", "lang/ja.js",
		"lang/zh-CN.js", "lang/zh-TW.js",
	} {
		if _, err := fs.Stat(minFS, p); err != nil {
			t.Errorf("asset %s missing after minification: %v", p, err)
		}
	}

	// app.js is genuinely smaller and keeps every global the HTML's data-on*
	// attributes call by name (the delegation runs new Function on the raw
	// attribute text, so a renamed function would ReferenceError on click).
	appSrc, _ := fs.ReadFile(base, "app.js")
	appMin, _ := fs.ReadFile(minFS, "app.js")
	if len(appMin) >= len(appSrc) {
		t.Errorf("app.js not minified: src=%d min=%d", len(appSrc), len(appMin))
	}
	for _, id := range []string{
		"selectDashboardPage", "openAddStaticPeerModal", "closeConfigModal",
		"i18nDict", "latestStatsData",
	} {
		if !bytes.Contains(appMin, []byte(id)) {
			t.Errorf("minified app.js lost identifier %q", id)
		}
	}

	// theme.js is the other synchronous <head> script; its globals must survive
	// too (toggleTheme is referenced from an HTML data-onclick attribute).
	themeSrc, _ := fs.ReadFile(base, "theme.js")
	themeMin, _ := fs.ReadFile(minFS, "theme.js")
	if len(themeMin) >= len(themeSrc) {
		t.Errorf("theme.js not minified: src=%d min=%d", len(themeSrc), len(themeMin))
	}
	if !bytes.Contains(themeMin, []byte("toggleTheme")) {
		t.Error("minified theme.js lost identifier toggleTheme")
	}

	// index.html keeps the exact placeholder comment the per-request locale
	// injection replaces, and keeps every behavioral attribute.
	htmlMin, _ := fs.ReadFile(minFS, "index.html")
	if !bytes.Contains(htmlMin, []byte(localePlaceholder)) {
		t.Error("minified index.html lost the locale placeholder comment")
	}
	for _, attr := range []string{"data-onclick", "data-i18n", "data-i18n-ph", "src="} {
		if !bytes.Contains(htmlMin, []byte(attr)) {
			t.Errorf("minified index.html lost attribute %q", attr)
		}
	}

	// CSS is genuinely smaller.
	cssSrc, _ := fs.ReadFile(base, "styles.css")
	cssMin, _ := fs.ReadFile(minFS, "styles.css")
	if len(cssMin) >= len(cssSrc) {
		t.Errorf("styles.css not minified: src=%d min=%d", len(cssSrc), len(cssMin))
	}

	// The theme beautification (the dark bg gradient that styles.css defines for
	// <html>, the ambient aurora overlay and its keyframes) must be part of the
	// served stylesheet too — a minifier that dropped these would ship a flat,
	// near-black page with no drift.
	for _, rule := range []string{"--bg-gradient", "auroraDrift", "body::before"} {
		if !bytes.Contains(cssMin, []byte(rule)) {
			t.Errorf("minified styles.css lost theme rule %q", rule)
		}
	}

	// Locale packs are JS and shrink too.
	langSrc, _ := fs.ReadFile(base, "lang/zh-CN.js")
	langMin, _ := fs.ReadFile(minFS, "lang/zh-CN.js")
	if len(langMin) >= len(langSrc) {
		t.Errorf("lang/zh-CN.js not minified: src=%d min=%d", len(langSrc), len(langMin))
	}
}

// TestMinifyFSFreshReaderPerOpen guards against serving the same file twice
// from one reader: the stdlib http.FileServer reads each Open to EOF, so a
// cached reader would return zero bytes on the second request.
func TestMinifyFSFreshReaderPerOpen(t *testing.T) {
	base := testStaticSub(t)
	minFS, err := buildMinifiedFS(base)
	if err != nil {
		t.Fatal(err)
	}
	read := func() []byte {
		f, err := minFS.Open("app.js")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		buf, err := io.ReadAll(f)
		if err != nil {
			t.Fatal(err)
		}
		return buf
	}
	if !bytes.Equal(read(), read()) {
		t.Error("second Open returned different bytes (reader was consumed)")
	}
	if _, err := minFS.Open("definitely-missing.js"); err == nil {
		t.Error("Open on a missing file should error")
	}
}

// TestServeLocalizedIndexMinified verifies the minified index.html still serves
// the negotiated locale pack and replaces the placeholder, end to end.
func TestServeLocalizedIndexMinified(t *testing.T) {
	base := testStaticSub(t)
	minFS, err := buildMinifiedFS(base)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Language", "zh-CN")
	serveLocalizedIndex(rec, req, minFS)

	body := rec.Body.String()
	if !strings.Contains(body, `lang/zh-CN.js`) {
		t.Error("zh-CN pack was not injected into the minified index.html")
	}
	if !strings.Contains(body, `p2ptapLocaleHint`) {
		t.Error("locale hint was not injected")
	}
	if strings.Contains(body, localePlaceholder) {
		t.Error("locale placeholder was not replaced")
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("unexpected content-type %q", ct)
	}
}

// TestMinifyMimeType pins the file classes that get minified vs. passed through.
func TestMinifyMimeType(t *testing.T) {
	cases := map[string]string{
		"index.html":      "text/html",
		"app.js":          "application/javascript",
		"styles.css":      "text/css",
		"favicon.svg":     "",
		"icon.png":        "",
		"lang/zh-CN.js":   "application/javascript",
		"something.weird": "",
	}
	for p, want := range cases {
		if got := minifyMimeType(p); got != want {
			t.Errorf("minifyMimeType(%q)=%q want %q", p, got, want)
		}
	}
}
