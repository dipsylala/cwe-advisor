# CWE-117: Improper Output Neutralization for Logs - JavaScript

## LLM Guidance

Log Injection in JavaScript/Node.js occurs when untrusted user input is written to logs without sanitization, allowing attackers to forge log entries, inject newlines to create fake events, or manipulate log analysis tools. Node.js applications using winston, bunyan, pino, or console.log are vulnerable when logging user-controlled data containing control characters (ASCII 0x00-0x1F, DEL 0x7F, C1 controls 0x80-0x9F, Unicode line separators U+0085/U+2028/U+2029), or ANSI escape codes. Fix by encoding all control characters before logging or using structured JSON logging.

## Key Principles

- Use structured JSON logging (winston, bunyan, pino) which automatically encodes control characters within field values
- Encode ALL control characters if using plain text logging: ASCII controls (0x00-0x1F), DEL (0x7F), C1 controls (0x80-0x9F), Unicode line separators (U+0085, U+2028, U+2029), and ANSI escape sequences
- Avoid string concatenation/interpolation when building log messages with user-controlled data
- Configure logging frameworks to automatically escape or sanitize user input fields
- Validate and sanitize all user-controlled data at application boundaries before it reaches logging code

## Taint Sinks

`console.log()` with raw input, `winston`/`bunyan`/`pino` logger calls using string interpolation instead of structured fields

## Remediation Steps

- Identify all locations where user input (params, headers, body) is logged
- Switch to structured JSON logging (winston with `format: winston.format.json()`, or bunyan/pino) passing user data as separate fields instead of string interpolation
- For plain text logging, encode control characters as backslash escapes (`\r`, `\n`, `\t`, and `\\` for the backslash itself) with a `\uXXXX` fallback for the rest, so a literal backslash-n and a real newline do not render identically
- Configure logger settings to auto-sanitize or use libraries like `validator` to clean inputs
- Add input validation at entry points to reject or sanitize data with control characters
- Test by attempting to inject newlines, null bytes, ANSI codes, and Unicode line separators - verify proper encoding
