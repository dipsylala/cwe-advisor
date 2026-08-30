# CWE-117: Improper Output Neutralization for Logs - Python

## LLM Guidance

Log injection occurs when untrusted data is written to logs without proper encoding, allowing attackers to inject newline characters to forge entries, CRLF sequences to split entries, or escape sequences to manipulate output. Encode at the call site to close a reported finding; `python-json-logger` and `structlog` are durable secondary controls, not substitutes - both serialize via `json.dumps` by default, which with its default `ensure_ascii=True` escapes the full range this entry cares about (ASCII controls, DEL, and non-ASCII code points including U+0085/U+2028/U+2029), but a project that sets `ensure_ascii=False` for readability loses that coverage for DEL and the Unicode separators.

## Key Principles

- Encode the value at the call site first, regardless of what the logging backend does
- Never concatenate user input directly into log messages
- Encode ALL control characters if manual logging required: ASCII controls (0x00-0x1F), DEL (0x7F), Unicode line separators (U+0085, U+2028, U+2029), and ANSI escape sequences
- Parameterize log messages using `%` or `{}` formatting
- Treat all external input (user data, headers, API responses) as untrusted
- Redact in a `logging.Filter` or a custom `Formatter` that rewrites both `record.msg` and `record.args`, not `record.msg` alone: a parameterized call (`logger.info("User input: %s", value)`) leaves `value` in `record.args`, so a filter that only encodes `record.msg` lets the payload through unchanged when the message is formatted
- Passing a reserved `LogRecord` attribute name in `extra` (`extra={"message": ...}` or `extra={"name": ...}`) raises `KeyError` at the call site rather than being silently dropped
- Escape with `repr()` or `json.dumps()` on the value rather than a hand-rolled replace: both render control characters as escape sequences and keep the backslash unambiguous, so `admin\nFAKE` typed literally and a real newline do not produce the same output
- Where structured JSON logging is not available, ESAPI-style `encodeForSingleLineTextLog()` semantics are what to reproduce: encode the whole ASCII control range plus U+0085, U+2028 and U+2029

## Taint Sinks

`logger.info()`/`logging.warning()` with f-string concatenation, `print()` with raw input

## Remediation Steps

- Encode the value at the call site before logging it - `json.dumps()` or `repr()` on the value covers the ASCII control range and keeps the backslash unambiguous. This closes the reported line whatever handlers the application turns out to have configured
- Fix every sink in that file, not only the reported one - a leftover `print()` or an `except` block still using an f-string keeps the finding live
- Use parameterized messages (`logger.info("Login for %s", username)`) or structured fields (`extra={"user": username}`), not f-strings. On its own this neutralizes nothing: it separates message from value so an encoding-aware formatter *can* act, which is why it accompanies the encoding rather than replacing it
- Where the same value is logged from many places, put the encoding in a `logging.Filter` or custom `Formatter` so it applies to every call site rather than the ones that remember
- As a separate, durable change, move the application to structured logging - `python-json-logger` or `structlog`, configured on every handler. Do not offer this as the fix for one finding: it needs a pinned version and reformats every line the application emits
- Test by attempting to inject newlines, null bytes, ANSI codes, and Unicode line separators - verify proper encoding
