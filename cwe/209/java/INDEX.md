# CWE-209: Generation of Error Message Containing Sensitive Information - Java

## LLM Guidance

Error Message Information Leak occurs when Java applications expose exception stack traces, SQL errors, or internal system details through HTTP responses, logs, or error pages. Java's detailed exception hierarchy aids debugging but becomes dangerous when exposed to untrusted users.

**Primary Defence:** Return generic error messages to users while logging detailed exceptions server-side using `@ControllerAdvice` or exception handlers to centralize error handling.

## Key Principles

- Centralize exception handling with `@ControllerAdvice` or JAX-RS `@Provider` mappers to ensure consistent, generic error responses
- Return generic messages to clients while logging full exception details server-side with unique error IDs for correlation
- `server.error.include-stacktrace` and `server.error.include-message` already default to `never` as of Spring Boot 2.3, so a finding here usually means one was explicitly set to `always`, not that the app needs new configuration. Spring Boot 4.0 renamed the whole prefix to `spring.web.error.*` - check the Boot version before naming either form
- Sanitize validation errors to avoid exposing internal field names, patterns, or business rules
- Redact sensitive data (passwords, tokens, PII) from logs using custom layouts or filters
- `BasicErrorController` and "the whitelabel page" are not the same thing: `BasicErrorController` is the bean that handles `/error` for both JSON (API clients) and HTML (browsers), and only falls back to the whitelabel HTML view when no custom `error` view is registered. Disabling `BasicErrorController` removes the whole `/error` mechanism, including the JSON path API clients rely on - to remove only the HTML fallback, set `whitelabel.enabled=false` on the same property prefix instead. Keep a controller-advice handler as well: an exception thrown outside a controller never reaches it and still lands on `BasicErrorController`
- Keep the stack trace out of the log *pattern* as well as the response: a `PatternLayoutEncoder` with `%ex` writes the full trace, so decide deliberately which appender carries it and who can read that destination

## Taint Sinks

`ex.getMessage()`/`ex.printStackTrace()` in response body, `server.error.include-stacktrace=always`, default Whitelabel error page

## Remediation Steps

- Configure Spring Boot to disable exception details - set `server.error.include-exception=false`, `include-stacktrace=never`, `include-message=never`
- Implement `@RestControllerAdvice` with `@ExceptionHandler` methods that log full details with UUID error IDs but return generic messages
- Create custom `ErrorResponse` class with generic message, error ID, and timestamp (no stack traces or internal details)
- Add JAX-RS exception mappers (`ExceptionMapper<T>`) for REST services to handle exceptions consistently
- For a custom HTML error page, add a file under an `/error` resource directory (e.g. `src/main/resources/public/error/404.html`, or a `5xx` template) rather than a `web.xml` `<error-page>` mapping - Spring Boot's default packaging has no `web.xml` at all, since it runs an embedded servlet container; `web.xml` only applies to the legacy WAR-deployment path
- Implement log redaction using custom Logback layouts with regex patterns for passwords, tokens, and PII
