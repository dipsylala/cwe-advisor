# CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute - JavaScript

## LLM Guidance

Sensitive Cookie Without 'Secure' Flag occurs when cookies containing sensitive data (session IDs, authentication tokens) are set without the `secure` attribute, allowing transmission over unencrypted HTTP connections. This exposes cookies to man-in-the-middle attacks, network sniffing, and session hijacking. The fix is to always set the `secure` flag on sensitive cookies to ensure they're only transmitted over HTTPS.

## Key Principles

- Always set `secure: true` on cookies containing sensitive data (sessions, auth tokens, CSRF tokens)
- Combine with `httpOnly: true` to prevent JavaScript access and `sameSite: 'strict'` or `'lax'` for CSRF protection
- Use framework-specific secure session configuration (express-session, cookie-session) with `secure` enabled
- Ensure application runs on HTTPS in production; cookies with `secure` flag won't work over HTTP
- Apply secure cookies globally via middleware or default session configuration
- Choose `SameSite` per flow rather than defaulting to `Strict`, which withholds the cookie from inbound links, SSO redirects and OAuth callbacks and presents as an unexplained logged-out state
- Behind a proxy, Express needs `app.set('trust proxy', ...)` before `secure: true` cookies are issued, or the session middleware sees HTTP and silently omits the flag

## Taint Sinks

`res.cookie()` without `secure: true`, `res.setHeader('Set-Cookie', ...)`, `express-session`/`cookie-session` config without `secure: true`

## Remediation Steps

- Identify all cookie-setting operations using `res.cookie()`, `res.setHeader('Set-Cookie')`, or session libraries
- Add `secure: true` flag to every cookie containing sensitive information
- Enable `httpOnly: true` to prevent XSS-based cookie theft
- Set `sameSite: 'strict'` or `'lax'` to mitigate CSRF attacks
- Configure session middleware (express-session) with secure cookie defaults
- Verify HTTPS is enforced in production (cookies with `secure` won't transmit over HTTP)
