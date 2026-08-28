# CWE-117: Improper Output Neutralization for Logs - C#

## LLM Guidance

Log Injection occurs when untrusted data is written to log files without sanitization, allowing attackers to forge log entries, hide malicious activity, or inject malicious content into log viewing tools.

The primary defence is structured logging with JSON formatters (Microsoft.Extensions.Logging with JSON output or Serilog), which automatically encode control characters within structured fields. For manual logging, encode all control characters: ASCII controls (0x00-0x1F), DEL (0x7F), C1 controls (0x80-0x9F), and Unicode line separators (U+0085, U+2028, U+2029).

## Key Principles

- Use structured logging frameworks with JSON formatters to isolate user data in properly escaped fields
- Never concatenate user input directly into log message strings
- If structured logging is unavailable, encode ALL control characters: ASCII controls (0x00-0x1F), DEL (0x7F), C1 controls (0x80-0x9F), Unicode line separators (U+0085, U+2028, U+2029)
- Validate and sanitize log inputs at application boundaries
- Use parameterized logging with message templates instead of string interpolation

## Taint Sinks

`ILogger.LogInformation($"...")` with string interpolation, `Console.WriteLine()` with raw input, unescaped CR/LF written to a plain-text log

## Remediation Steps

- Encode the value at the call site before logging it: escape the ASCII control range (0x00-0x1F, 0x7F), U+0085, U+2028, U+2029, and the backslash itself, so a literal backslash-n and a real newline do not render identically. This closes the reported line whatever formatter the application turns out to be configured with
- Fix every sink in that file, not only the reported one - a `catch` block or a leftover `Console.WriteLine`/`Trace.WriteLine` still interpolating keeps the finding live
- Replace interpolation with a message template - `logger.LogInformation("User {Username} logged in", username)`. On its own this neutralizes nothing: it separates template from value so an encoding-aware sink *can* act, which is why it accompanies the encoding rather than replacing it
- As a separate, durable change, adopt structured logging with `Microsoft.Extensions.Logging` and a JSON formatter, or Serilog with JSON sinks. Do not offer this as the fix for one finding: it depends on the sinks the application already has, and it reformats every line it emits
- Test by attempting to inject newlines, null bytes, and Unicode line separators - verify proper encoding
