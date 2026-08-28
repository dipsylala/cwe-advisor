# CWE-209: Generation of Error Message Containing Sensitive Information

## LLM Guidance

Error Message Information Leak occurs when detailed error messages expose sensitive information about the application's internal structure, configuration, or data to users. This includes stack traces, file paths, database errors, SQL queries, and system configuration details. The core fix is to display only generic error messages to users while logging detailed information server-side.

## Key Principles

- Never expose internal error details to clients; error responses must come from a fixed, server-controlled contract
- Disable the framework's own debug error page for production (Flask debug mode, ASP.NET's developer exception page, Spring Boot's whitelabel page) - an application-level handler returning clean JSON is bypassed by any exception that reaches it
- Suppress the exception class name and vendor error code too: `PSQLException` or `SqlException` names the engine and driver. The test for any client-visible message or code is whether it describes the *caller's situation* or *your architecture* - `Resource not found` and `Authentication failed` are facts about the request; anything a reader could use to sketch the stack belongs in the log behind an opaque error ID
- Check the chain: a message built as `"Payment failed: " + cause.getMessage()` looks generic and still ships the lower-level detail
- Separate user-facing messages from internal diagnostic information
- Use generic messages in production: "An error occurred", "Invalid credentials", "Request failed"
- Log detailed errors server-side for debugging and monitoring
- Avoid user enumeration through error message differences

## Remediation Steps

- Review flaw details to identify where detailed error messages are exposed
- Trace the error flow from exception handling to user response
- Implement generic error messages for all production error responses
- Configure error handlers (404, 500, API errors) to return sanitized messages
- Add server-side logging for full error details including stack traces
- Validate that error responses don't leak paths, queries, or configuration details - including the validation layer's default body, which nobody wrote and so nobody reviews: FastAPI/Pydantic's 422 includes an `input` key holding the rejected value, Spring's `ObjectError.toString()` renders `rejected value [...]`, and `express-validator`'s `errors.array()` carries a `value` per entry, so a registration or password-change endpoint echoes the submitted password back and writes it into every access log on the way. Build the response from the field name plus a message you wrote, and log field paths rather than values
- Keep status codes and response timing identical across error types that must be indistinguishable, and register the framework's HTTP-exception type ahead of any catch-all handler - a catch-all on the base exception type turns a 404, 405 or 413 into a 500, which leaks nothing and breaks every client that distinguishes them
