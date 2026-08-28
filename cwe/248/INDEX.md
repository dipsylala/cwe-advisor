# CWE-248: Uncaught Exception

## LLM Guidance

Uncaught exceptions cause application crashes, expose sensitive information through stack traces (file paths, internal logic, SQL queries), and enable denial of service attacks. They also leave resources unclosed and abort critical operations mid-execution.

## Key Principles

- Never allow exceptions to crash services - implement global exception handlers
- Protect sensitive information - catch exceptions before stack traces leak internals
- Ensure resource cleanup - use try-finally or automatic resource management
- Handle async operations - catch promise rejections and async/await errors
- Provide safe fallbacks - return error responses instead of crashing

## Remediation Steps

- Wrap risky operations in try-catch blocks - I/O operations, parsing, external API calls, database queries
- Add global exception handlers - implement application-level handlers for uncaught exceptions and unhandled promise rejections
- Use promise error handling - add `.catch()` to promises or use try-catch with async/await
- Implement proper resource cleanup - use try-finally blocks or language-specific constructs (using, with, defer); a try/catch added around only the risky call still skips a close that sits after the try block
- Cover the asynchronous paths too: a promise chain, async task, or callback with no rejection handler still escapes, just on a different execution path
- Disabling the framework's debug error page without installing a boundary handler leaves the process crashing or returning an opaque error rather than failing gracefully
- Route by what actually failed: a *return value* nobody reads is CWE-252, an exception caught into an empty block is CWE-1069, and the disclosure when a caught exception's contents reach the caller is CWE-209
- Validate inputs before processing - check data types and formats before parsing or processing
- Log errors securely - capture exception details in logs without exposing them to users
