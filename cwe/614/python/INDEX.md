# CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute - Python

## LLM Guidance

Sensitive Cookie Without 'Secure' Flag occurs when cookies containing authentication tokens, session IDs, or other sensitive data are transmitted without the `Secure` flag, allowing them to be sent over unencrypted HTTP connections. This exposes cookies to interception through man-in-the-middle attacks and network sniffing. The fix requires setting `secure=True` on all sensitive cookies and enforcing HTTPS.

## Key Principles

- Always set `secure=True` for cookies containing sensitive data (sessions, auth tokens, user identifiers)
- Enforce HTTPS site-wide and redirect HTTP requests to HTTPS
- Set `httponly=True` to prevent JavaScript access to sensitive cookies
- Use `samesite='Strict'` or `'Lax'` to prevent CSRF attacks
- Configure framework session settings to use secure defaults
- In Django set `SESSION_COOKIE_SECURE = True` and `CSRF_COOKIE_SECURE = True` together - the CSRF cookie is a separate setting and is the one usually left behind
- `SECURE_SSL_REDIRECT` needs `SECURE_PROXY_SSL_HEADER` configured when TLS terminates at a proxy, or Django sees plain HTTP and either loops or leaves the flag off
- Set `HttpOnly` and a per-flow `SameSite` alongside `Secure`; `Strict` also withholds the cookie from inbound links and SSO callbacks

## Taint Sinks

`response.set_cookie()` without `secure=True`, `SESSION_COOKIE_SECURE` and `CSRF_COOKIE_SECURE` left unset/false in Django settings

## Remediation Steps

- Identify all locations where cookies are set in your application
- Add `secure=True` parameter to all sensitive cookie assignments
- Configure framework session management to enable secure cookies by default - in Flask set `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, and `SESSION_COOKIE_SAMESITE` via `app.config.update()`
- Enable HTTPS across your entire application infrastructure
- Set additional security flags - `httponly=True` and `samesite='Strict'/'Lax'`
- Test that cookies are not transmitted over HTTP connections
