# CWE-613: Insufficient Session Expiration - Java

## LLM Guidance

A servlet session's timeout is `HttpSession.setMaxInactiveInterval(int)` in seconds, and if nobody sets it the container's own default applies silently - Tomcat's is 30 minutes via `conf/web.xml`'s `<session-timeout>`, and Spring Boot's embedded server matches that default through `server.servlet.session.timeout`. A JWT built with jjwt has no such default: `Jwts.builder().expiration(Date)` is entirely caller-set, and while the default parser does validate `exp` and throws `ExpiredJwtException` once it has passed, nothing stops a caller from setting `exp` a decade out, and nothing built into jjwt or Spring Security revokes a still-valid token before then. Spring Security's `SessionRegistry` gives concurrent-session control and manual invalidation for the servlet-session case; a JWT needs its own revocation store if it must be invalidated before `exp`.

## Key Principles

- `HttpSession.setMaxInactiveInterval(int)` takes seconds; zero or negative means the session never times out. If the codebase never calls it, the container's own default applies silently - Tomcat's is 30 minutes (`conf/web.xml`'s `<session-timeout>`), and an app-level `web.xml` can raise it without anyone touching code
- Spring Boot's `server.servlet.session.timeout` (also 30 minutes by default on embedded Tomcat) accepts a bare number as seconds or a `Duration` shorthand like `15m` - a raw integer meant as minutes silently becomes seconds
- jjwt enforces no maximum lifetime on `Jwts.builder().expiration(Date)` (0.12+; `setExpiration(Date)` pre-0.12) - the value is entirely caller-chosen, and the default parser validating `exp` and throwing `ExpiredJwtException` only means an *already-expired* token is rejected, not that the chosen lifetime was reasonable
- There is no built-in JWT revocation in jjwt or plain Spring Security. Closing the pre-expiry-revocation gap means a `jti`-keyed store checked before trusting the token, or a short-lived access token paired with a separately revocable refresh token
- For servlet sessions, `SessionManagementConfigurer.maximumSessions(n)` limits concurrent sessions (invalidating the oldest, or with `.maxSessionsPreventsLogin(true)` rejecting the new login instead), and `SessionRegistry.getSessionInformation(id).expireNow()` invalidates a specific session on demand - but `SessionRegistry` only tracks sessions if `HttpSessionEventPublisher` is registered as a listener, which is easy to skip
- Distinguish `nbf`/`iat` bookkeeping from the actual fix: jjwt validates those claims too where present, but that only checks the token isn't used *too early* - it says nothing about whether `exp` was set to a sane value in the first place

## Taint Sinks

`Jwts.builder().expiration(...)` set implausibly far out or omitted, a JWT verification path with no corresponding revocation check, `HttpSession.setMaxInactiveInterval(-1)` or an excessively large value, `SessionRegistry` used without `HttpSessionEventPublisher` registered

## Remediation Steps

- Locate - find `Jwts.builder()` calls and `HttpSession.setMaxInactiveInterval`/session-timeout configuration
- Trace what the session or token authorizes, to size the lifetime to the risk
- Identify the unsafe pattern - an `.expiration()` set far out or left to a copied example, a container-default session timeout nobody chose deliberately, or a `SessionRegistry` with no `HttpSessionEventPublisher` wired up
- Replace with an explicit, risk-sized `.expiration()` and `setMaxInactiveInterval`
- Bind, encode, validate, or authorize - add a `jti`-keyed revocation store for tokens needing pre-expiry invalidation, or move to short-lived access plus refresh tokens; wire `HttpSessionEventPublisher` so `SessionRegistry` can see and invalidate sessions
- Harden configuration - use `maximumSessions()`/`maxSessionsPreventsLogin()` where concurrent-session limits matter
- Test - confirm a token or session issued before the fix is rejected once its new, shorter lifetime passes, and that a revoked token or an `expireNow()`-invalidated session is rejected on the very next request
