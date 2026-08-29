# CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting') - Python

## LLM Guidance

HTTP Response Splitting in Python occurs when user-supplied strings are placed into HTTP response headers without validation. Both major stacks reject CR and LF on header assignment - Werkzeug raises `ValueError`, Django raises `BadHeaderError` - so the typical finding is not a splittable response but an unhandled 500, plus the redirect *target*, which no character check addresses. The genuinely unprotected paths are lower-level WSGI or ASGI responses that never touch a framework header object.

## Key Principles

- Werkzeug's `Headers` checks values only, and says so: its keys are documented as "assumed to be trusted... must not come from untrusted user input", so a header *name* built from input is unchecked. Django checks both, running the same CR/LF test over the key
- **Flask and Django diverge on `redirect()`, and the entry point matters.** Werkzeug's `redirect()` assigns the location straight to the header, so a CR/LF target raises. Django's `HttpResponseRedirect` runs `iri_to_uri()` first, which percent-encodes CR/LF to `%0D%0A` - so `BadHeaderError` never fires there and the value is silently transformed instead
- Both checks are `[\r\n]` only. Neither catches U+0085, U+2028 or U+2029 - and none of those becomes a CR or LF octet on the wire, so validate for the grammar you want rather than for a list of Unicode terminators
- Validate redirect destinations against an allowlist of permitted paths, or parse with `urllib.parse.urlparse()` and check scheme and host - `startswith('/')` accepts `//evil.example` as a protocol-relative URL
- Do not filter percent-encoded `%0d`/`%0a` out of input. WSGI servers decode the query string before the view sees it, so an encoded payload arrives as literal CR LF and is already caught; removing the three-character string only corrupts legitimate values
- Django's own history is the argument for validating at the source rather than trusting the raise: every header-injection CVE it has had - CVE-2015-5144, CVE-2021-32052, CVE-2026-53878 - was a validator upstream accepting a newline, never `HttpResponse` failing to reject one
- **Do not use `secure_filename()` for a `Content-Disposition` filename.** Werkzeug documents it as making a name "safe to use on a regular filesystem and in `os.path.join`"; it NFKD-normalizes then drops every non-ASCII character, so a name in another script becomes nothing, and its docstring warns it "may produce an empty string". Use `send_file(..., download_name=...)` (Flask 2.0+) instead, which emits an ASCII `filename` plus the RFC 5987 `filename*=UTF-8''` form
- Use `re.fullmatch()` for validation. That alone closes the `$`-before-trailing-newline hole, which only bites `match()`/`search()`; note `\z` is not a valid escape before Python 3.14 and raises `re.PatternError`, so the strict anchor to pair with `match()` is the capital `\Z`

## Taint Sinks

`response.headers[...]=`, `response.headers.add()`, `HttpResponse[...]=` (Django), `make_response()`, `start_response()` in a bare WSGI app, ASGI `send({"type": "http.response.start", "headers": [...]})`

## Remediation Steps

- Replace manual `response.headers['Location'] = user_input` with `redirect(validated_url)` (Flask/Django)
- Validate redirect URLs - confirm they are relative paths or belong to an allowed origin using `urllib.parse` - since neither framework's CR/LF check constrains the destination
- Validate any other header value against the characters that header's grammar permits, using `re.fullmatch()`, and reject rather than edit
- Check the lower-level paths the framework check does not cover: a bare WSGI `start_response`, an ASGI `http.response.start`, or middleware that rebuilds the header list
- For a download filename, use `send_file(..., download_name=...)` rather than sanitizing the name yourself
- In Django, use typed response classes or `response.set_cookie()` for cookies rather than assigning headers with user data
- Test by submitting `%0d%0aX-Injected: evil` and a literal `\r\n` in inputs that end up in headers, and separately submit `//evil.example` as a redirect target, since the CRLF test passes whether or not the open redirect is closed
