package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

func main() {
	htmlData, _ := os.ReadFile("pkg/web/static/index.html")
	jsData, _ := os.ReadFile("pkg/web/static/app.js")
	combinedLines := append(strings.Split(string(htmlData), "\n"), strings.Split(string(jsData), "\n")...)
	lines := strings.Split(string(jsData), "\n")

	// 1. Extract referenced keys from data-i18n / data-i18n-ph attributes
	refSet := map[string]bool{}
	attrRe := regexp.MustCompile(`data-i18n(-ph)?="([^"]+)"`)
	for _, line := range combinedLines {
		for _, m := range attrRe.FindAllStringSubmatch(line, -1) {
			refSet[m[2]] = true
		}
		tRe := regexp.MustCompile(`\bt\(\s*['"]([^'"]+)['"]\s*\)`)
		for _, m := range tRe.FindAllStringSubmatch(line, -1) {
			refSet[m[1]] = true
		}
	}
	falsePositives := map[string]bool{
		"/": true, "2d": true, ":": true, "a": true,
		"content-type": true, "tr": true, "textarea": true, "": true,
	}
	refs := []string{}
	for k := range refSet {
		if falsePositives[k] {
			continue
		}
		refs = append(refs, k)
	}
	sort.Strings(refs)

	// 2. Detect language block header lines: e.g. `en: {` or `"zh-CN": {`
	headerRe := regexp.MustCompile(`^\s*([\"']?[a-zA-Z\-]+[\"']?)\s*:\s*\{`)
	type langBlock struct {
		lang  string
		start int
		end   int
	}
	var headers []langBlock
	for i, line := range lines {
		if m := headerRe.FindStringSubmatch(line); m != nil {
			lang := strings.Trim(m[1], "\"'")
			if isKnownLang(lang) {
				headers = append(headers, langBlock{lang: lang, start: i, end: i})
			}
		}
	}
	knownLangs := []string{"en", "zh-CN", "zh-TW", "ja", "de", "es", "fr"}
	// sort headers by line
	sort.Slice(headers, func(a, b int) bool { return headers[a].start < headers[b].start })
	// assign end = next header start - 1
	for idx := range headers {
		if idx+1 < len(headers) {
			headers[idx].end = headers[idx+1].start - 1
		} else {
			headers[idx].end = len(lines) - 1
		}
	}

	// 3. For each language, collect keys defined in its line range via `key:`
	keyRe := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|true|false|\d+)`)
	langKeys := map[string]map[string]bool{}
	langVals := map[string]map[string]string{}
	for _, h := range headers {
		keys := map[string]bool{}
		vals := map[string]string{}
		for i := h.start; i <= h.end; i++ {
			line := lines[i]
			for _, m := range keyRe.FindAllStringSubmatch(line, -1) {
				key := m[1]
				v := m[2]
				if strings.HasPrefix(v, `"`) || strings.HasPrefix(v, `'`) {
					v = v[1 : len(v)-1]
					v = strings.ReplaceAll(v, `\"`, `"`)
					v = strings.ReplaceAll(v, `\'`, `'`)
				}
				keys[key] = true
				vals[key] = v
			}
		}
		langKeys[h.lang] = keys
		langVals[h.lang] = vals
	}

	fmt.Printf("Referenced keys: %d\n", len(refs))
	fmt.Printf("Languages found: %d\n", len(headers))
	for _, h := range headers {
		fmt.Printf("  %s: %d keys (lines %d-%d)\n", h.lang, len(langKeys[h.lang]), h.start+1, h.end+1)
	}

	// 4. Report missing per language, with English source value
	fmt.Println("\n=== Missing keys per language ===")
	for _, lang := range knownLangs {
		keys, ok := langKeys[lang]
		if !ok {
			fmt.Printf("\n[%s] NOT FOUND\n", lang)
			continue
		}
		missing := []string{}
		for _, r := range refs {
			if !keys[r] {
				missing = append(missing, r)
			}
		}
		if len(missing) > 0 {
			fmt.Printf("\n[%s] missing %d keys:\n", lang, len(missing))
			for _, m := range missing {
				fmt.Printf("  - %s  ||  en=%q\n", m, langVals["en"][m])
			}
		} else {
			fmt.Printf("\n[%s] OK (all referenced keys present)\n", lang)
		}
	}

	// 5. Keys referenced but present in NONE of the languages
	fmt.Println("\n=== Keys referenced but absent in ALL languages ===")
	for _, r := range refs {
		present := false
		for _, lang := range knownLangs {
			if langKeys[lang][r] {
				present = true
				break
			}
		}
		if !present {
			fmt.Printf("  ? %s\n", r)
		}
	}
}

func isKnownLang(s string) bool {
	switch s {
	case "en", "zh-CN", "zh-TW", "ja", "de", "es", "fr":
		return true
	}
	return false
}
