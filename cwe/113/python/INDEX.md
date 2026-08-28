# CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting') - Python

## LLM Guidance

HTTP Response Splitting in Python occurs when user-supplied strings are placed into HTTP response headers without stripping CRLF characters. In Flask, `response.headers['Location'] = user_input` and `make_response()` with user-derived header values are the typical sinks. Django's `HttpResponse` rejects embedded `\r`/`\n` in any header value assignment (raising `BadHeaderError`), whether set via `redirect()` or via `response['Header-Name'] = user_input` directly - both go through the same underlying check. The real gap is redirect *target* validation (an attacker-controlled URL can still point off-site) and any lower-level WSGI header construction that bypasses Django's `HttpResponse` class entirely. Sanitize all user input before it enters any header value, and validate redirect targets against an allowlist.

## Key Principles

- Strip `\r` (U+000D), `\n` (U+000A), and their percent-encoded equivalents (`%0d`, `%0a`) from any value placed in a response header
- Also strip Unicode line terminators: U+0085 (NEL), U+2028 (LINE SEPARATOR), U+2029 (PARAGRAPH SEPARATOR)
- Use `flask.redirect()` or `django.shortcuts.redirect()` with a validated URL instead of setting `Location` manually
- Validate redirect destinations against an allowlist of permitted paths or use `urllib.parse.urlparse()` to confirm the scheme and host are safe
- Avoid `response.headers.add()` with unsanitized user input; prefer framework-level cookie and header helpers
- Werkzeug's `Headers.set()` and Django's `HttpResponse.__setitem__` raise `ValueError`/`BadHeaderError` for CR or LF, so an unvalidated value is a 500 rather than a split response - fix the validation rather than relying on the raise
- Anchor the validation with `re.fullmatch()`: `$` in Python's `re` also matches before a trailing newline, and `\z` is not a valid escape before Python 3.14, so `re.compile(r'\A[a-z]+\z')` raises rather than protecting anything

## Taint Sinks

`response.headers[...]=`, `response.headers.add()`, `HttpResponse[...]=` (Django), `make_response()`

## Remediation Steps

- Replace manual `response.headers['Location'] = user_input` with `redirect(validated_url)` (Flask/Django)
- Validate redirect URLs - confirm they are relative paths or belong to an allowed origin using `urllib.parse`
- Strip CRLF and Unicode line terminators before any `response.headers[...] = user_input` assignment; also strip percent-encoded `%0d` and `%0a`
- For `Content-Disposition` headers (file downloads), use `werkzeug.utils.secure_filename()` and encode the filename
- In Django, avoid `HttpResponse` header assignment with user data; use typed response classes or `response.set_cookie()` for cookies
- Test by submitting `%0d%0aX-Injected: evil` in inputs that end up in headers
