# CWE-209: Generation of Error Message Containing Sensitive Information - Java

## LLM Guidance

Error Message Information Leak occurs when Java applications expose exception stack traces, SQL errors, or internal system details through HTTP responses, logs, or error pages. Java's detailed exception hierarchy aids debugging but becomes dangerous when exposed to untrusted users.

**Primary Defence:** Return generic error messages to users while logging detailed exceptions server-side using `@ControllerAdvice` or exception handlers to centralize error handling.

## Key Principles

- Centralize exception handling with `@ControllerAdvice` or JAX-RS `@Provider` mappers to ensure consistent, generic error responses
- Return generic messages to clients while logging full exception details server-side with unique error IDs for correlation
- Disable detailed error responses in production Spring Boot configuration (`server.error.include-stacktrace=never`)
- Sanitize validation errors to avoid exposing internal field names, patterns, or business rules
- Redact sensitive data (passwords, tokens, PII) from logs using custom layouts or filters
- Disable or replace Spring Boot's `BasicErrorController` (the whitelabel page) for production rather than relying on the application's own handler to catch everything - an exception thrown outside a controller reaches it
- Keep the stack trace out of the log *pattern* as well as the response: a `PatternLayoutEncoder` with `%ex` writes the full trace, so decide deliberately which appender carries it and who can read that destination

## Taint Sinks

`ex.getMessage()`/`ex.printStackTrace()` in response body, `server.error.include-stacktrace=always`, default Whitelabel error page

## Remediation Steps

- Configure Spring Boot to disable exception details - set `server.error.include-exception=false`, `include-stacktrace=never`, `include-message=never`
- Implement `@RestControllerAdvice` with `@ExceptionHandler` methods that log full details with UUID error IDs but return generic messages
- Create custom `ErrorResponse` class with generic message, error ID, and timestamp (no stack traces or internal details)
- Add JAX-RS exception mappers (`ExceptionMapper<T>`) for REST services to handle exceptions consistently
- Configure custom error pages in `web.xml` pointing to `/WEB-INF/error-pages/` to prevent direct access
- Implement log redaction using custom Logback layouts with regex patterns for passwords, tokens, and PII
