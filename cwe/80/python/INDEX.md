# CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) - Python

## LLM Guidance

CWE-80 is the subset of CWE-79 covering injection of script-related HTML tags into output. In Python it appears where a value reaches the page without the template layer escaping it. Django autoescapes every variable by default; Jinja2 does **not** - a bare `jinja2.Environment()` has autoescaping off, and Flask turns it on only for certain file extensions. So the first question is not "is escaping enabled" but "is it enabled for *this* template".

**Primary Defence:** Django's default autoescaping, or Jinja2 with autoescaping explicitly configured; `html.escape()` where HTML is built in Python.

## Key Principles

- **Jinja2's `autoescape` defaults to `False`.** Flask enables it for templates ending `.html`, `.htm`, `.xml`, `.xhtml` and `.svg` via `render_template()`, and for every string passed to `render_template_string()`. A template named `.txt`, `.j2`, `.tpl` or with no extension gets none. Outside Flask, pass `autoescape=True` or `select_autoescape()` to the `Environment` yourself
- **`{% autoescape on %}` is Django syntax and silently does the opposite in Jinja.** Jinja parses the tag argument as an expression, so `on` is an undefined name, which is falsy - the block *disables* escaping, with no error. Jinja's spelling is `{% autoescape true %}`
- Django escapes five characters in every variable by default - `<`, `>`, `'`, `"`, `&`. Its own documented failure case is the unquoted attribute: `<style class={{ var }}>` is exploitable through `class1 onmouseover=...` even with autoescaping on, because no escaped character is needed. Quote your attributes
- Never mark untrusted data safe: `mark_safe()`, the `|safe` filter, `markupsafe.Markup()`, and a custom filter declaring `is_safe`. Where a small HTML fragment must be built in Python, `django.utils.html.format_html()` is the documented alternative - it escapes every argument the way the template layer would, so no call site can forget one
- For a JavaScript context, use the vendor mechanism rather than plain JSON. Django's `json_script` filter (2.1+; the element id became optional in 4.1) escapes `<`, `>` and `&` to `<`, `>`, `&` and wraps the result in a `<script type="application/json">` tag to be read with `JSON.parse`, which plain `json.dumps` does not do. Jinja's `|tojson` is the equivalent, with the documented exception that it is not safe inside a double-quoted HTML attribute
- `html.escape()` (3.2+) escapes those same five characters, since `quote` defaults to `True`. The docs scope it to HTML body and quoted-attribute use - it is not a JavaScript, CSS, or URL encoder
- **`bleach` is finished, not merely deprecated.** Its README states: "Bleach is no longer maintained. There will be no future releases including for security issues." The repository is archived, 6.4.0 (June 2026) is the last release, and it carries an advisory for `linkify(parse_email=True)` with no fixed version and no prospect of one. Use `nh3` (bindings to the Rust `ammonia` sanitizer) for HTML sanitization instead
- Content Security Policy remains defence-in-depth; Django's `json_script` is documented as compatible with a strict policy that forbids in-page script execution

## Taint Sinks

`django.utils.safestring.mark_safe()`, `|safe`, `markupsafe.Markup()`, `jinja2.Environment(autoescape=False)`, `{% autoescape off %}`/`{% autoescape false %}`, `format_html()` with an untrusted *format string*

## Remediation Steps

- Audit templates for `|safe`, `mark_safe()`, or HTML built by string concatenation with user data
- Confirm autoescaping actually applies to the template in hand - check the file extension under Flask, and check the `Environment` construction outside it
- Replace manual HTML construction with `format_html()` or template rendering, or `html.escape()` for a plain value
- For JavaScript contexts, use Django's `json_script` or Jinja's `|tojson` rather than embedding a `json.dumps` result
- Quote every HTML attribute that interpolates a variable, since escaping alone does not cover an unquoted one
- For unavoidable raw HTML, sanitize with `nh3` and a strict allowlist
- Add CSP headers to restrict inline scripts
- Test with `<script>alert(1)</script>` and `<img src=x onerror=alert(1)>`, and confirm legitimate text containing `<`, `>` and `&` still renders correctly
