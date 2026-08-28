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

- Encode the value at the call site before logging it: escape the ASCII control range (0x00-0x1F, 0x7F), U+0085, U+2028, U+2029, ANSI escape sequences, and the backslash itself, so a literal backslash-n and a real newline do not render identically. This closes the reported line whatever transport the application is configured with
- Fix every sink in that file, not only the reported one - a leftover `console.error()` or a `catch` block still interpolating keeps the finding live, and a redacting format only covers the logger instance it is attached to
- Pass user data as separate fields rather than interpolating it into the message. On its own this neutralizes nothing: it separates message from value so an encoding-aware transport *can* act, which is why it accompanies the encoding rather than replacing it
- As a separate, durable change, move the application to structured JSON logging - winston with `format: winston.format.json()`, or bunyan/pino. Do not offer this as the fix for one finding: it reformats every line the application emits
- Add input validation at entry points to reject or sanitize data with control characters
- Test by attempting to inject newlines, null bytes, ANSI codes, and Unicode line separators - verify proper encoding
