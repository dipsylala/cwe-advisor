# CWE-117: Improper Output Neutralization for Logs - JavaScript

## LLM Guidance

Log Injection in JavaScript/Node.js occurs when untrusted user input is written to logs without sanitization, allowing attackers to forge log entries, inject newlines to create fake events, or manipulate log analysis tools. Encode at the call site to close a finding: winston, bunyan, and pino all serialize JSON output through `JSON.stringify` (or an equivalent with the same escaping rules), which escapes the ASCII control range (0x00-0x1F) plus quote and backslash, but does not escape DEL (0x7F) or the Unicode line separators U+0085/U+2028/U+2029 - those pass through raw even in a JSON log line. Of the three, bunyan has had no release since 2021 and no commits since 2023; prefer winston or pino, both actively maintained.

## Key Principles

- Encode the value before logging it, regardless of formatter: ASCII controls (0x00-0x1F), DEL (0x7F), U+0085, U+2028, U+2029, ANSI escape sequences, and the backslash itself
- Structured JSON logging (winston, pino) is a durable secondary control, not a substitute - `JSON.stringify`-based serialization covers 0x00-0x1F and `"`/`\` automatically but not DEL or the Unicode line separators
- Avoid string concatenation/interpolation when building log messages with user-controlled data
- Prefer winston or pino over bunyan for new code; bunyan's last release was 2021
- Passing a whole untrusted object as metadata (`logger.info("Event received", req.body)`) is not the same fix as encoding a string value: JSON-encoding protects each value, but an attacker-controlled key still becomes a new top-level field - measured on winston 3, a `timestamp` key overwrites the generated one and a `message` key appends to the real message. Pick only the specific fields to log rather than passing the object through

## Taint Sinks

`console.log()` with raw input, `winston`/`bunyan`/`pino` logger calls using string interpolation instead of structured fields

## Remediation Steps

- Encode the value at the call site before logging it: escape the ASCII control range (0x00-0x1F, 0x7F), U+0085, U+2028, U+2029, ANSI escape sequences, and the backslash itself, so a literal backslash-n and a real newline do not render identically. Write these as JS escape sequences - `\x00` through `\x1F`, `\x7F`, `\u0085`, `\u2028`, `\u2029` - inside the replacement pattern, not as literal raw characters pasted into the source file: an unescaped U+2028/U+2029 embedded directly in a regex or template literal is itself an illegal LineTerminator in that position and throws a SyntaxError. This closes the reported line whatever transport the application is configured with
- Fix every sink in that file, not only the reported one - a leftover `console.error()` or a `catch` block still interpolating keeps the finding live, and a redacting format only covers the logger instance it is attached to
- Pass user data as separate fields rather than interpolating it into the message. On its own this neutralizes nothing: it separates message from value so an encoding-aware transport *can* act, which is why it accompanies the encoding rather than replacing it
- As a separate, durable change, move the application to structured JSON logging - winston with `format: winston.format.json()`, or pino. Do not offer this as the fix for one finding: it reformats every line the application emits, and `JSON.stringify`-based serialization still does not cover DEL or the Unicode line separators, so the call-site encoding above stays necessary
- Test by attempting to inject newlines, null bytes, ANSI codes, and Unicode line separators - verify proper encoding
