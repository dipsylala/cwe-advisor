# CWE-113: HTTP Response Splitting - Python

## LLM Guidance

HTTP Response Splitting in Python occurs when user-supplied strings are placed into HTTP response headers without stripping CRLF characters. In Flask, `response.headers['Location'] = user_input` and `make_response()` with user-derived header values are the typical sinks. Django's `HttpResponseRedirect` and `redirect()` perform some validation on the URL, but manually setting headers via `response['Header-Name'] = user_input` does not. Sanitize all user input before it enters any header value, or use framework redirect helpers with validated URLs.

## Key Principles

- Strip `\r` (U+000D), `\n` (U+000A), and their percent-encoded equivalents (`%0d`, `%0a`) from any value placed in a response header
- Also strip Unicode line terminators: U+0085 (NEL), U+2028 (LINE SEPARATOR), U+2029 (PARAGRAPH SEPARATOR)
- Use `flask.redirect()` or `django.shortcuts.redirect()` with a validated URL instead of setting `Location` manually
- Validate redirect destinations against an allowlist of permitted paths or use `urllib.parse.urlparse()` to confirm the scheme and host are safe
- Avoid `response.headers.add()` with unsanitized user input; prefer framework-level cookie and header helpers

## Remediation Steps

- Replace manual `response.headers['Location'] = user_input` with `redirect(validated_url)` (Flask/Django)
- Validate redirect URLs — confirm they are relative paths or belong to an allowed origin using `urllib.parse`
- Strip CRLF and Unicode line terminators before any `response.headers[...] = user_input` assignment; also strip percent-encoded `%0d` and `%0a`
- For `Content-Disposition` headers (file downloads), use `werkzeug.utils.secure_filename()` and encode the filename
- In Django, avoid `HttpResponse` header assignment with user data; use typed response classes or `response.set_cookie()` for cookies
- Test by submitting `%0d%0aX-Injected: evil` in inputs that end up in headers

## Safe Pattern

```python
import re
from urllib.parse import urlparse
from flask import Flask, redirect, request, abort, make_response

app = Flask(__name__)

ALLOWED_REDIRECT_PATTERN = re.compile(r'^/[a-zA-Z0-9/_\-]*$')
CRLF_PATTERN = re.compile(r'[\r\n\u0085\u2028\u2029]|%0[aAdD]')

def sanitize_header_value(value: str) -> str:
    return CRLF_PATTERN.sub('', value)

# Safe redirect — validate before redirecting
@app.route('/redirect')
def safe_redirect():
    url = request.args.get('next', '/')
    if not ALLOWED_REDIRECT_PATTERN.match(url):
        abort(400)
    return redirect(url)

# Safe custom header — strip CRLF first
@app.route('/download')
def download():
    filename = sanitize_header_value(request.args.get('filename', 'file.txt'))
    response = make_response('file contents')
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response
```
