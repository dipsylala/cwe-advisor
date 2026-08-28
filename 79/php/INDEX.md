# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - PHP

## LLM Guidance

XSS occurs when untrusted data is rendered in web pages without proper encoding, allowing attackers to inject malicious scripts. Always use `htmlspecialchars()` with `ENT_QUOTES | ENT_HTML5` flags and UTF-8 encoding for HTML output, or leverage framework auto-escaping (Laravel Blade `{{ }}`, Twig `{{ }}`). Apply context-specific encoding for JavaScript, URLs, and CSS contexts.

## Key Principles

- Use output encoding appropriate to the context (HTML, JavaScript, URL, CSS): `htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8')` for markup, `json_encode()` with `JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT` inside `<script>` - the tag and amp flags alone leave quotes able to close an attribute the script sits in, `urlencode()`/`rawurlencode()` for URL components
- Include `ENT_SUBSTITUTE` so invalid UTF-8 becomes a replacement character rather than an empty string - without it a malformed byte sequence silently drops the whole value, which hides the bug rather than encoding it. `htmlentities()` is not a stronger `htmlspecialchars()`; it converts more characters but neutralizes the same ones
- Enable auto-escaping in templating engines by default
- Where rich HTML genuinely has to render, `{!! !!}` and `|raw` are safe only over already-sanitized input: run it through HTML Purifier (`ezyang/htmlpurifier`, or `mews/purifier` in Laravel) or Symfony's `HtmlSanitizer` (6.1+) with a tag allowlist, and keep escaping everywhere else
- Never trust user input or data from external sources
- Implement Content Security Policy (CSP) headers as defence-in-depth
- Validate and sanitize input at application boundaries

## Taint Sinks

`echo`/`print` unescaped, Blade `{!! !!}`, Twig `|raw`, `$_GET`/`$_POST` echoed directly

## Remediation Steps

- Replace all unencoded output with `htmlspecialchars($data, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8')`
- Use framework escaping - Laravel `{{ $var }}` instead of `{!! $var !!}`, Twig `{{ var }}` not `{{ var|raw }}`
- For JavaScript contexts, use `json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT)`
- For URLs, apply `urlencode()` or `rawurlencode()` to user data
- Review all instances of `echo`, `print`, and template rendering
- Add CSP header - `Content-Security-Policy: default-src 'self'`
