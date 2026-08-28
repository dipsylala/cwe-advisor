# CWE-117: Improper Output Neutralization for Logs

## LLM Guidance

Log Injection occurs when untrusted user input is written to logs without proper validation or encoding, allowing attackers to forge log entries, hide malicious activity, or inject misleading information. This can compromise audit trails, inject false data into monitoring systems, or obscure security incidents.

## Key Principles

- Ideally, use structured JSON/ECS logging to separate data from structure
- If JSON/ECS logging is not possible, always encode untrusted input so it appears as data values, not log control characters
- Never concatenate user input directly into log messages - and note that a parameterized call (`logger.info("User: {}", username)`) neutralizes nothing by itself: it keeps the template and the value separate so the sink *can* encode, which makes it a prerequisite for the JSON sink rather than a substitute for it
- Never hand-build a JSON-looking line by concatenation - a value containing a quote or brace forges or breaks out of the field exactly as a newline would in plain text
- Attach request-scoped values through the framework's context features (SLF4J/Logback MDC, .NET `LogContext`, Python `contextvars`) so they inherit the sink's encoding instead of being spliced into the message
- Validate and sanitize all external data before logging
- Configure logging frameworks to auto-escape or encode fields

## Remediation Steps

- Review security findings to identify where untrusted data is written to logs
- Locate the source where untrusted data enters (HTTP parameters, headers, cookies, files, databases, network requests)
- Trace to the sink by finding the logging statement (see the language-specific guidance's Taint Sinks for concrete function names)
- Check the data flow through each frame in the data path for missing encoding or validation
- Encode at the call site to close the reported line, and treat moving the application to structured JSON/ECS logging as a separate, durable change - it depends on the logging backend actually in use and reformats every line the application emits, so it is not a drop-in fix for one finding
- Explicitly encode the whole ASCII control range (`\x00-\x1F`, `\x7F`) plus the Unicode separators U+0085, U+2028 and U+2029, and the backslash itself - without escaping the backslash, an attacker who types the two characters `\` and `n` produces output identical to a real newline and the log stops recording which arrived
- Encode rather than strip: removing the characters prevents forging and also removes the evidence that an attempt was made, which is what an incident responder needs
- Truncate before encoding, so a length cut cannot land inside an escape sequence, and disable ANSI colour output in production or encode the escape codes
- JSON encoding always escapes the ASCII control range, but encoders differ on U+0085/U+2028/U+2029 and several emit them raw. Raw separators only forge an entry where a line-oriented stage runs before the parser - Python's `str.splitlines()` and Java's `Scanner` treat all three as terminators, while `BufferedReader.readLine()` and .NET's `StringReader.ReadLine()` do not
- Configure the JSON layout to emit one event per line (an end-of-event delimiter) and confirm nothing prepends a timestamp or level to the object - a line that is only mostly JSON breaks the aggregator that parses it
- Fix every sink, not the reported one: a `console.log`/`print`/`Trace.WriteLine` debug statement, a `catch` block, or a second appender that still writes unencoded text leaves the finding live
