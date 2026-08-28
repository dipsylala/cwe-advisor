# CWE-201: Insertion of Sensitive Information Into Sent Data - Java

## LLM Guidance

Java applications commonly leak sensitive information through HTTP responses, error messages, exception stack traces, and API responses. While frameworks like Spring Boot and Jakarta EE provide security features, misconfigurations and improper exception handling can expose passwords, tokens, internal paths, PII, database credentials, and system details. The core fix is sanitizing all output, implementing global exception handlers, and using structured logging with sensitive data filtering.

## Key Principles

- Implement global exception handlers that return sanitized error responses without stack traces or internal details
- Use structured logging with explicit filtering of sensitive fields (passwords, tokens, API keys)
- Configure frameworks to disable detailed error pages and debug information in production
- Validate and sanitize all data before including in responses, especially user-controlled input
- Apply principle of least privilege to error messages - only expose what users need
- `management.endpoints.web.exposure.include=*` publishes every Actuator endpoint, including `/env`, `/configprops` and `/heapdump` - expose the specific endpoints needed and put them behind authentication
- An entity's generated `toString()` includes every field, so logging or returning the object publishes columns the API never declared
- Extend `ResponseEntityExceptionHandler` (or an equivalent boundary handler) so an unhandled exception cannot render the framework's default body, and build the response from fields you chose

## Taint Sinks

`ResponseEntity.body(entity)` with unfiltered entities, `ex.getMessage()`/`ex.printStackTrace()` returned to clients, `server.error.include-stacktrace=always`

## Remediation Steps

- Replace default exception handlers with a `@RestControllerAdvice` class whose `@ExceptionHandler` methods log full details server-side but return generic messages to clients
- Configure `server.error.include-stacktrace=never` and `server.error.include-message=never` in Spring Boot
- Audit all API responses and DTOs to ensure no sensitive fields are serialized using `@JsonIgnore` or custom serializers
- Implement structured logging with masking patterns for sensitive data
- Review exception handling to catch specific exceptions and avoid leaking implementation details
- Add response filters to strip sensitive headers and sanitize error content
