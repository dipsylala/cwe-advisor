# CWE-352: Cross-Site Request Forgery (CSRF) - Java

## LLM Guidance

CSRF vulnerabilities in Java web applications occur when state-changing endpoints don't verify that requests originated from the application itself, allowing attackers to execute unauthorized actions on behalf of authenticated users. Spring Security provides built-in CSRF protection using synchronizer tokens that must be included in state-changing requests. The defence requires enabling CSRF protection, including tokens in forms/AJAX calls, and using appropriate HTTP methods (POST/PUT/DELETE for state changes).

## Key Principles

- Enable Spring Security CSRF protection (enabled by default in Spring Boot)
- Include CSRF tokens in all state-changing requests (POST, PUT, DELETE, PATCH)
- Use SameSite cookie attributes to provide defence-in-depth
- Validate CSRF tokens on the server side for all non-safe HTTP methods
- Never disable CSRF protection globally without explicit security review
- Generate the token with `SecureRandom` and compare it with `MessageDigest.isEqual()`, which is constant-time - Spring Security's `CsrfFilter` does both, so the finding is usually a filter that was disabled or a path excluded from it
- Bind the token to the `HttpSession` and re-issue it when the session is regenerated at login, so a pre-authentication token cannot be replayed

## Taint Sinks

`@PostMapping`/`@PutMapping`/`@DeleteMapping` with `http.csrf().disable()`, an over-broad `ignoringRequestMatchers(...)` exclusion, or a missing `_csrf` token

## Remediation Steps

- Add Spring Security dependency and enable CSRF protection in configuration
- Include a hidden field named `${_csrf.parameterName}` with value `${_csrf.token}` in all HTML forms; for AJAX send the token in the `X-CSRF-TOKEN` header, or in `X-XSRF-TOKEN` when the app uses `CookieCsrfTokenRepository.withHttpOnlyFalse()`, the repository that lets JavaScript read the cookie in the first place
- Configure SameSite=Strict or Lax on session cookies
- Use POST/PUT/DELETE for state-changing operations (never GET)
- Ensure Spring Security's CSRF filter is active in the filter chain
- Test that requests without valid tokens are rejected with 403 Forbidden
