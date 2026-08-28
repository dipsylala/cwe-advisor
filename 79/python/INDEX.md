# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Python

## LLM Guidance

XSS occurs when untrusted data is included in web output without proper encoding, allowing attackers to inject malicious scripts. Python frameworks like Django and Flask provide auto-escaping in templates-use `{{ variable }}` syntax and keep auto-escaping enabled. For manual encoding, use `html.escape()` or an HTML sanitizer with allowlists for rich content - `bleach` is widely used but is in reduced/security-fix-only maintenance; `nh3` (Python bindings to Rust's `ammonia`) is the actively maintained alternative for new code.

## Key Principles

- Use framework auto-escaping: Django templates escape by default, and Flask enables Jinja2 autoescaping for `.html`/`.xhtml`/`.xml` templates - a standalone `jinja2.Environment` does not autoescape unless constructed with `autoescape=True`, and `render_template_string()` follows the same rule
- Use the Django filter matching the context - `escapejs` inside a `<script>` block, `urlencode` for a URL component - rather than relying on the default HTML escaping everywhere
- Never mark untrusted input as safe: Avoid `|safe`, `mark_safe()`, or `Markup()` on user data
- Context-aware encoding: Use HTML escaping for HTML context, JavaScript encoding for `<script>` blocks
- Sanitize rich content: Use `bleach.clean()` or `nh3.clean()` with strict allowlists for permitted HTML tags/attributes - prefer `nh3` for new code since `bleach` is in reduced maintenance
- Validate input format: Reject unexpected formats early before rendering

## Taint Sinks

`mark_safe()`, `|safe` filter, `Markup()`, `render_template_string()` with concatenated HTML

## Remediation Steps

- Enable and verify template auto-escaping is active (Django - `TEMPLATES['OPTIONS']['autoescape'] = True`)
- Replace `mark_safe()` or `|safe` filters on user-controlled variables with proper escaping
- Use `html.escape()` when rendering user input in non-template contexts
- For rich HTML, use `bleach.clean(user_input, tags=['b', 'i', 'u'], attributes={})` with minimal allowlists
- Set `Content-Security-Policy` headers to restrict script execution
- Audit all template rendering and ensure no raw user input reaches the DOM
