# CWE-352: Cross-Site Request Forgery (CSRF) - Java

## LLM Guidance

CSRF vulnerabilities in Java web applications occur when state-changing endpoints don't verify that requests originated from the application itself, allowing attackers to execute unauthorized actions on behalf of authenticated users. Spring Security provides built-in CSRF protection using synchronizer tokens that must be included in state-changing requests. The defence requires enabling CSRF protection, including tokens in forms/AJAX calls, and using appropriate HTTP methods (POST/PUT/DELETE for state changes).

## Key Principles

- Enable Spring Security CSRF protection (enabled by default in Spring Boot)
- Include CSRF tokens in all state-changing requests (POST, PUT, DELETE, PATCH)
- Use SameSite cookie attributes to provide defence-in-depth
- Validate CSRF tokens on the server side for all non-safe HTTP methods
- Never disable CSRF protection globally without explicit security review
- Generation and comparison are different classes: `HttpSessionCsrfTokenRepository` (the default token store) mints each token with `UUID.randomUUID()`, and `CsrfFilter` compares the submitted value against it with `MessageDigest.isEqual()`, which is constant-time - so the finding is usually a filter that was disabled or a path excluded from it, not a weak generator
- Bind the token to the `HttpSession` and re-issue it when the session is regenerated at login, so a pre-authentication token cannot be replayed

## Taint Sinks

`@PostMapping`/`@PutMapping`/`@DeleteMapping` with `http.csrf().disable()`, an over-broad `ignoringRequestMatchers(...)` exclusion, or a missing `_csrf` token

## Remediation Steps

- Add Spring Security dependency and enable CSRF protection in configuration
- Include a hidden field named `${_csrf.parameterName}` with value `${_csrf.token}` in all HTML forms; for AJAX send the token in the `X-CSRF-TOKEN` header, or in `X-XSRF-TOKEN` when the app uses `CookieCsrfTokenRepository.withHttpOnlyFalse()`, the repository that lets JavaScript read the cookie in the first place
- `withHttpOnlyFalse()` alone is not enough for a JavaScript client: the default `XorCsrfTokenRequestAttributeHandler` (Spring Security 6.0+) BREACH-encodes the token server-side, so the plain value JavaScript reads from the cookie will not match it. Pair the cookie repository with `SpaCsrfTokenRequestHandler` (or the `csrf.spa()` shortcut on newer versions) so the value handed to JavaScript and the value validated are the same encoding
- Configure SameSite=Strict or Lax on session cookies
- Use POST/PUT/DELETE for state-changing operations (never GET)
- Ensure Spring Security's CSRF filter is active in the filter chain
- Test that requests without valid tokens are rejected with 403 Forbidden
