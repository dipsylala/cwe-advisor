# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Go

## LLM Guidance

XSS in Go usually stems from using `text/template` for HTML output, building HTML with string concatenation or `fmt.Fprintf`, or disabling auto-escaping by wrapping untrusted input in `template.HTML`/`template.JS`/`template.URL`. The primary remediation is `html/template`, which performs context-aware escaping (HTML body, attribute, JavaScript, CSS, URL) automatically; `text/template` must never render browser-facing HTML.

## Key Principles

- Always render HTML with `html/template`, never `text/template`, for any output served to a browser
- Never wrap untrusted input in `template.HTML`, `template.JS`, `template.URL`, `template.CSS`, or `template.HTMLAttr` - these disable escaping for that value
- Keep an entire response inside one parsed template so context-aware escaping applies consistently; do not mix `fmt.Fprintf` writes with `template.Execute` for the same output
- For JSON APIs, set `Content-Type: application/json` via `json.NewEncoder`/`w.Header`, never `text/html`, so responses cannot be interpreted as HTML
- If HTML fragments must be built outside a parsed template, note that `html/template` exports only `HTMLEscapeString`, `JSEscapeString` and `URLQueryEscaper` - there is no attribute or CSS escaper, so a value landing in an unquoted attribute or a `style` context cannot be escaped correctly by hand. Move those cases back inside a parsed template rather than approximating one
- Where user-supplied rich HTML must render, sanitize with `github.com/microcosm-cc/bluemonday` (`UGCPolicy()`) and wrap only its output in `template.HTML`; that wrapper is otherwise the sink, not the fix
- If input selects a link, resource, or class via an allowlist, resolve it through a Go map lookup and pass only the resolved value into the template

## Taint Sinks

`template.HTML()`, `template.JS()`, `template.URL()`, `template.HTMLAttr()`, `text/template.Execute()`, `w.Write()` with concatenated HTML

## Remediation Steps

- Locate - find HTML rendering sinks: `template.Execute`/`ExecuteTemplate`, `w.Write` with HTML strings, `fmt.Fprintf` writing HTML
- Trace data flow - follow request, query, form, or header data into template data structs or concatenated strings
- Replace the unsafe pattern - convert `text/template` to `html/template`, or replace string concatenation with a parsed `html/template`
- Bind, encode, validate, or authorize - let `html/template`'s context-aware escaping handle output encoding; do not hand-roll an escaper
- Break taint after allowlist validation - if input feeds a URL or resource selection, resolve it through an allowlist map first and only pass the resolved value into the template
- Harden configuration - add a `Content-Security-Policy` header (`default-src 'self'; script-src 'self'`) as defence-in-depth
- Test - verify with `<script>`, event-handler, and attribute-breakout payloads (for example `"><svg onload=...>`) in each output context
