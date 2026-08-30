# CWE-209: Generation of Error Message Containing Sensitive Information - Python

## LLM Guidance

Error Message Information Leak occurs when Python applications expose sensitive details through exception tracebacks, debug output, or verbose error messages in responses. These leaks reveal file paths, code structure, library versions, SQL queries, and internal logic to attackers. Return generic error messages to users while logging detailed exceptions securely server-side.

## Key Principles

- Separate user-facing and internal error handling: Show generic messages to clients, log full details securely
- Disable debug mode in production: Set `DEBUG=False` in Django/Flask and disable verbose tracebacks
- Sanitize all error responses: Never expose stack traces, file paths, or internal state in API/web responses
- Use structured logging: Log exceptions with context to secure locations inaccessible to users
- In Flask, a bare `@app.errorhandler(Exception)` does catch `HTTPException` subclasses (404, 405, etc.) unless a more specific `HTTPException` handler is also registered - Flask dispatches by exception-class specificity, not registration order, so the fix is adding that specific handler, not reordering. FastAPI does not have this trap: it always registers its own `HTTPException` handler at app construction, and Starlette's dispatch keeps that separate from whatever a broad `@app.exception_handler(Exception)` catches, so a 404 stays a 404 there by default. FastAPI has a different, real trap in the same area: a custom handler must be registered on `starlette.exceptions.HTTPException`, not `fastapi.HTTPException` - the latter is a subclass, and Starlette's own router raises the bare parent class for a missing route or disallowed method, so a handler keyed to the subclass never sees them and those cases fall through to FastAPI's default body instead
- Redact `record.msg` *and* `record.args` in a logging filter, since the message is not interpolated until it is formatted

## Taint Sinks

`str(e)`/`traceback.format_exc()` in response, Django `DEBUG=True` error pages, Flask `app.run(debug=True)`

## Remediation Steps

- Implement custom exception handlers that return generic HTTP error responses - this is what closes a handler that returns the exception text, and it holds regardless of how the environment is configured
- Configure production settings to disable debug mode and detailed error pages
- Add centralized logging for all exceptions with full traceback details, using `logger.error(..., exc_info=True)` so the traceback goes to the log rather than the response
- Review all try-except blocks to ensure user-facing messages are generic
- Implement error monitoring with tools that capture exceptions server-side
- Test error scenarios to verify no sensitive information leaks through responses
