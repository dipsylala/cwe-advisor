# CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute - Java

## LLM Guidance

Sensitive cookies in Java web applications transmitted without the `secure` attribute can be intercepted over HTTP connections, enabling man-in-the-middle attacks and session hijacking. The fix requires setting `setSecure(true)` on all cookies containing authentication tokens, session IDs, or other sensitive data to ensure transmission only over HTTPS.

## Key Principles

- Set `secure` attribute to `true` on all cookies containing sensitive information
- Enforce HTTPS-only transmission for authentication and session cookies
- Apply `HttpOnly` flag alongside `Secure` to prevent client-side script access
- Configure framework-level defaults for secure cookie creation
- Validate that production environments use HTTPS exclusively
- Set it in configuration rather than per cookie where the container supports it: `server.servlet.session.cookie.secure=true` (plus `http-only` and `same-site`) covers `JSESSIONID`, which application code never creates - but it governs only the container-managed session cookie. A `Cookie`/`NewCookie` built manually elsewhere (auth token, remember-me, CSRF) does not inherit this setting and still needs `.setSecure(true)`/`.secure(true)` called on that specific object
- On Jakarta Servlet 6.0+ (Jakarta EE 10, e.g. Tomcat 10.1+/Jetty 12+), `jakarta.servlet.http.Cookie` has a generic `setAttribute("SameSite", "Strict")` method; on the older `javax.servlet.http.Cookie` (Servlet <=4.0, still common in Spring Boot 2.x apps) there is no such method at all. Elsewhere, set it through the container's session-cookie configuration, a `Set-Cookie` written via `ResponseCookie`, or - for `jakarta.ws.rs.core.NewCookie` at JAX-RS 3.1+ (Jakarta EE 10), which added a `NewCookie.Builder.sameSite(...)` method the older `javax.ws.rs` namespace lacks - and choose `Lax` or `Strict` per flow rather than defaulting to `Strict`

## Taint Sinks

`new Cookie()` without `setSecure(true)`, `ResponseCookie.from()` without `.secure(true)`, `SessionCookieConfig.setSecure()` left false

## Remediation Steps

- Identify all cookie creation points (Servlet `Cookie`, Spring `ResponseCookie`, framework configurations)
- Add `cookie.setSecure(true)` to every sensitive cookie instantiation
- Set `HttpOnly` flag with `cookie.setHttpOnly(true)` for additional protection
- Configure container defaults via `ServletContext.getSessionCookieConfig().setSecure(true)` and `.setHttpOnly(true)`, or build Spring cookies with `ResponseCookie.from(name, value).secure(true).httpOnly(true).build()`
- Test in HTTPS environment to verify cookies transmit only over secure channels
- Review session management configuration in `web.xml` or application properties
