# CWE-209: Generation of Error Message Containing Sensitive Information - Python

## LLM Guidance

Error Message Information Leak occurs when Python applications expose sensitive details through exception tracebacks, debug output, or verbose error messages in responses. These leaks reveal file paths, code structure, library versions, SQL queries, and internal logic to attackers. Return generic error messages to users while logging detailed exceptions securely server-side.

## Key Principles

- Separate user-facing and internal error handling: Show generic messages to clients, log full details securely
- Disable debug mode in production: Set `DEBUG=False` in Django/Flask and disable verbose tracebacks
- Sanitize all error responses: Never expose stack traces, file paths, or internal state in API/web responses
- Use structured logging: Log exceptions with context to secure locations inaccessible to users
- Register the framework's own HTTP exception ahead of a catch-all: `@app.errorhandler(Exception)` in Flask, or a broad handler in FastAPI, also catches `HTTPException`/`fastapi.HTTPException` and turns a 404 or 405 into a 500 - nothing leaks, so a re-scan passes while every client that distinguishes them breaks
- Redact `record.msg` *and* `record.args` in a logging filter, since the message is not interpolated until it is formatted

## Taint Sinks

`str(e)`/`traceback.format_exc()` in response, Django `DEBUG=True` error pages, Flask `app.run(debug=True)`

## Remediation Steps

- Configure production settings to disable debug mode and detailed error pages
- Implement custom exception handlers that return generic HTTP error responses
- Add centralized logging for all exceptions with full traceback details, using `logger.error(..., exc_info=True)` so the traceback goes to the log rather than the response
- Review all try-except blocks to ensure user-facing messages are generic
- Implement error monitoring with tools that capture exceptions server-side
- Test error scenarios to verify no sensitive information leaks through responses
