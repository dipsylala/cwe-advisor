# CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute - Java

## LLM Guidance

Sensitive cookies in Java web applications transmitted without the `secure` attribute can be intercepted over HTTP connections, enabling man-in-the-middle attacks and session hijacking. The fix requires setting `setSecure(true)` on all cookies containing authentication tokens, session IDs, or other sensitive data to ensure transmission only over HTTPS.

## Key Principles

- Set `secure` attribute to `true` on all cookies containing sensitive information
- Enforce HTTPS-only transmission for authentication and session cookies
- Apply `HttpOnly` flag alongside `Secure` to prevent client-side script access
- Configure framework-level defaults for secure cookie creation
- Validate that production environments use HTTPS exclusively
- Set it in configuration rather than per cookie where the container supports it: `server.servlet.session.cookie.secure=true` (plus `http-only` and `same-site`) covers `JSESSIONID`, which application code never creates
- The Servlet `Cookie` class has no `SameSite` setter - set it through the container's session-cookie configuration, a `Set-Cookie` written via `ResponseCookie`, or JAX-RS `NewCookie`, and choose `Lax` or `Strict` per flow rather than defaulting to `Strict`

## Taint Sinks

`new Cookie()` without `setSecure(true)`, `ResponseCookie.from()` without `.secure(true)`, `SessionCookieConfig.setSecure()` left false

## Remediation Steps

- Identify all cookie creation points (Servlet `Cookie`, Spring `ResponseCookie`, framework configurations)
- Add `cookie.setSecure(true)` to every sensitive cookie instantiation
- Set `HttpOnly` flag with `cookie.setHttpOnly(true)` for additional protection
- Configure container defaults via `ServletContext.getSessionCookieConfig().setSecure(true)` and `.setHttpOnly(true)`, or build Spring cookies with `ResponseCookie.from(name, value).secure(true).httpOnly(true).build()`
- Test in HTTPS environment to verify cookies transmit only over secure channels
- Review session management configuration in `web.xml` or application properties
