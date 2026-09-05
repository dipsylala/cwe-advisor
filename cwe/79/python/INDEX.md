# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Python

## LLM Guidance

XSS occurs when untrusted data is included in web output without proper encoding, allowing attackers to inject malicious scripts. Python frameworks like Django and Flask provide auto-escaping in templates-use `{{ variable }}` syntax and keep auto-escaping enabled. For manual encoding, use `html.escape()` or an HTML sanitizer with allowlists for rich content - `bleach` is classified `Development Status :: 7 - Inactive` on PyPI and is no longer maintained; `nh3` (Python bindings to Rust's `ammonia`) is the replacement.

## Key Principles

- Use framework auto-escaping: Django templates escape by default, and Flask enables Jinja2 autoescaping for `.html`/`.htm`/`.xhtml`/`.xml`/`.svg` templates and for `render_template_string()` - a standalone `jinja2.Environment` does not autoescape unless constructed with `autoescape=True`
- Use the Django filter matching the context - `escapejs` inside a `<script>` block, `urlencode` for a URL component - rather than relying on the default HTML escaping everywhere
- Never mark untrusted input as safe: Avoid `|safe`, `mark_safe()`, or `Markup()` on user data - truncating or `.format()`-ing a value first does not make it safe to wrap, since neither operation strips HTML
- `{% autoescape off %}` disables escaping for every variable in that block, not only the one it was added for - a block reused later for another variable silently loses protection
- Context-aware encoding: Use HTML escaping for HTML context, JavaScript encoding for `<script>` blocks
- Import `escape` and `Markup` from `markupsafe`, not from `flask`: the Flask re-exports were deprecated in 2.3.0 (April 2023) and are gone in 3.x, so `from flask import escape` raises `ImportError` at import time and takes the whole application down, not just the route being fixed (confirmed on Flask 3.1.3). The standard library's `html.escape()` is the dependency-free alternative
- Sanitize rich content with `nh3.clean()` and a strict tag/attribute allowlist; an existing `bleach.clean()` call is a dependency to replace, not a safe default to leave in place. An allowlist that permits `style` or event-handler attributes still lets CSS-based injection through even with `<script>` stripped
- `json.dumps()` does not escape `</script>`, so its output embedded in a `<script>` block lets a string value close the block early - in Django render through `{{ value|json_script:"id" }}` and read it back with `JSON.parse`, and in Jinja2 use `|tojson`, which escapes `<`, `>`, `&`, and `'`
- Validate input format: Reject unexpected formats early before rendering
- When the reported sink is `render_template_string()` with the value concatenated into the source, escaping the value does not close it: `html.escape()` leaves `{{`, `}}` and `{%` untouched and the string is still compiled as a Jinja2 template, so `{{ 7*191 }}` in an escaped value renders as `1337` (reproduced on Flask 3.1.3). Keep the template source constant and pass the value through the context - `render_template_string('<p>{{ term }}</p>', term=value)` - where autoescaping renders it as text

## Taint Sinks

`mark_safe()`, `|safe` filter, `Markup()`, `{% autoescape off %}` blocks, `render_template_string()` with concatenated HTML

## Remediation Steps

- Replace the `mark_safe()` or `|safe` on the reported line with proper escaping - that marker is what disables escaping for that value, and it stays disabled however the template engine is configured
- Confirm template auto-escaping is on (Django - `TEMPLATES['OPTIONS']['autoescape']`, true by default), so the rest of the template is covered
- Use `html.escape()` when rendering user input in non-template contexts
- Where user input is built into a `render_template_string()` source string, restructure so the source is a constant and the input arrives as a keyword argument; escaping the value is the wrong layer for that sink
- For rich HTML, use `nh3.clean(user_input, tags={'b', 'i', 'u'}, attributes={})` with minimal allowlists - `nh3` takes sets where `bleach` took lists
- Set `Content-Security-Policy` headers to restrict script execution
- Audit all template rendering and ensure no raw user input reaches the DOM
