# CWE-117: Improper Output Neutralization for Logs - Python

## LLM Guidance

Log injection occurs when untrusted data is written to logs without proper encoding, allowing attackers to inject newline characters to forge entries, CRLF sequences to split entries, or escape sequences to manipulate output. Use structured logging with JSON output (python-json-logger or structlog) to automatically encode control characters within fields, preventing log forging while preserving evidence.

## Key Principles

- Structured logging automatically handles encoding and prevents injection
- Never concatenate user input directly into log messages
- Encode ALL control characters if manual logging required: ASCII controls (0x00-0x1F), DEL (0x7F), C1 controls (0x80-0x9F), Unicode line separators (U+0085, U+2028, U+2029), and ANSI escape sequences
- Parameterize log messages using `%` or `{}` formatting
- Treat all external input (user data, headers, API responses) as untrusted
- Redact in a `logging.Filter` or a custom `Formatter` that rewrites `record.msg` and `record.args`, so it applies to every call site rather than the ones that remember
- Escape with `repr()` or `json.dumps()` on the value rather than a hand-rolled replace: both render control characters as escape sequences and keep the backslash unambiguous, so `admin\nFAKE` typed literally and a real newline do not produce the same output
- Where structured JSON logging is not available, ESAPI-style `encodeForSingleLineTextLog()` semantics are what to reproduce: encode the whole ASCII control range plus U+0085, U+2028 and U+2029

## Taint Sinks

`logger.info()`/`logging.warning()` with f-string concatenation, `print()` with raw input

## Remediation Steps

- Install structured logging library - `pip install python-json-logger` or `structlog`
- Configure every handler with `jsonlogger.JsonFormatter()` (python-json-logger) or the structlog JSON renderer
- Replace string concatenation with structured fields - `logger.info("Login", extra={"user": username})`
- Use parameterized messages with format strings, not f-strings in log calls
- For legacy systems without JSON logging, implement comprehensive control character encoding
- Test by attempting to inject newlines, null bytes, ANSI codes, and Unicode line separators - verify proper encoding
