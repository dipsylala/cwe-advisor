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

- Adopt structured logging with `Microsoft.Extensions.Logging` and JSON formatter or Serilog with JSON sinks
- Replace string concatenation/interpolation with parameterized logging - `logger.LogInformation("User {Username} logged in", username)`
- For legacy systems without structured logging, encode control characters as backslash escapes (`\r`, `\n`, `\t`, and `\\` for the backslash itself) with a `\uXXXX` fallback for the rest, so a literal backslash-n and a real newline do not render identically
- Configure log outputs to use structured formats (JSON, ECS) rather than plain text
- Review existing logging statements to ensure user input is passed as parameters, not embedded in format strings
- Test by attempting to inject newlines, null bytes, and Unicode line separators - verify proper encoding
