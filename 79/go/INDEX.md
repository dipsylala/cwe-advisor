# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Go

## LLM Guidance

XSS in Go usually stems from using `text/template` for HTML output, building HTML with string concatenation or `fmt.Fprintf`, or disabling auto-escaping by wrapping untrusted input in `template.HTML`/`template.JS`/`template.URL`. The primary remediation is `html/template`, which performs context-aware escaping (HTML body, attribute, JavaScript, CSS, URL) automatically; `text/template` must never render browser-facing HTML.

## Key Principles

- Always render HTML with `html/template`, never `text/template`, for any output served to a browser
- Never wrap untrusted input in `template.HTML`, `template.JS`, `template.URL`, `template.CSS`, or `template.HTMLAttr` - these disable escaping for that value
- Keep an entire response inside one parsed template so context-aware escaping applies consistently; do not mix `fmt.Fprintf` writes with `template.Execute` for the same output
- For JSON APIs, set `Content-Type: application/json` via `json.NewEncoder`/`w.Header`, never `text/html`, so responses cannot be interpreted as HTML
- If HTML fragments must be built outside a parsed template, use `template.HTMLEscapeString`, `template.JSEscapeString`, or `template.URLQueryEscaper` for the specific context, never a generic escaper
- If input selects a link, resource, or class via an allowlist, resolve it through a Go map lookup and pass only the resolved value into the template

## Remediation Steps

- Locate - find HTML rendering sinks: `template.Execute`/`ExecuteTemplate`, `w.Write` with HTML strings, `fmt.Fprintf` writing HTML
- Trace data flow - follow request, query, form, or header data into template data structs or concatenated strings
- Replace the unsafe pattern - convert `text/template` to `html/template`, or replace string concatenation with a parsed `html/template`
- Bind, encode, validate, or authorize - let `html/template`'s context-aware escaping handle output encoding; do not hand-roll an escaper
- Break taint after allowlist validation - if input feeds a URL or resource selection, resolve it through an allowlist map first and only pass the resolved value into the template
- Harden configuration - add a `Content-Security-Policy` header (`default-src 'self'; script-src 'self'`) as defence-in-depth
- Test - verify with `<script>`, event-handler, and attribute-breakout payloads (for example `"><svg onload=...>`) in each output context

## Safe Pattern

```go
// SAFE: html/template auto-escapes based on context
package main

import (
	"html/template"
	"net/http"
)

var tmpl = template.Must(template.New("greet").Parse(
	`<h1>Hello, {{.Name}}!</h1>`,
))

func greetHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// SAFE: {{.Name}} is escaped for the HTML body context automatically
	tmpl.Execute(w, struct{ Name string }{Name: name})
}
```
