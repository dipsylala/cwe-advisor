# CWE-117: Improper Output Neutralization for Logs - C#

## LLM Guidance

Log Injection occurs when untrusted data is written to log files without sanitization, allowing attackers to forge log entries, hide malicious activity, or inject malicious content into log viewing tools.

Encoding at the call site closes a reported finding regardless of formatter. Structured JSON logging helps but the two common choices differ: `Microsoft.Extensions.Logging`'s console JSON formatter uses `System.Text.Json`, whose `JavaScriptEncoder` escapes the full range this entry cares about (ASCII controls, DEL, and non-ASCII code points including U+0085/U+2028/U+2029) by default. Serilog's built-in JSON formatters (`JsonFormatter`, `CompactJsonFormatter`) only escape ASCII controls (0x00-0x1F) plus the backslash and quote - DEL (0x7F) and the Unicode line separators pass through unescaped, so a Serilog JSON sink still needs the manual encoding below.

## Key Principles

- Encode at the call site first: ASCII controls (0x00-0x1F), DEL (0x7F), U+0085, U+2028, U+2029, and the backslash itself, so a literal backslash-n and a real newline render differently. This closes the finding under any formatter, including Serilog's default JSON one
- Never concatenate user input directly into log message strings
- Structured JSON logging is a durable secondary control, not a substitute for the above: confirm which JSON path is configured, since `Microsoft.Extensions.Logging`'s `System.Text.Json`-based console formatter covers this entry's full range while Serilog's `JsonFormatter`/`CompactJsonFormatter` do not extend past 0x00-0x1F and `"`/`\`
- Validate and sanitize log inputs at application boundaries
- Use parameterized logging with message templates instead of string interpolation; the Roslyn analyzer rule CA2254 flags a non-constant (interpolated or concatenated) template passed to a logger method
- Serilog's `LogContext.PushProperty` only reaches the output once `.Enrich.FromLogContext()` is added at logger configuration time - without it, pushed properties are silently absent from every log line
- If validating for CR/LF instead of encoding, check after decoding: ASP.NET Core already URL-decodes `Request.Query`/`Request.Form`, so a raw-string check for `%0D%0A` never sees it, and re-decoding with `WebUtility.UrlDecode` corrupts literal `+`/`%` in the value

## Taint Sinks

`ILogger.LogInformation($"...")` with string interpolation, `Console.WriteLine()` with raw input, unescaped CR/LF written to a plain-text log

## Remediation Steps

- Encode the value at the call site before logging it: escape the ASCII control range (0x00-0x1F, 0x7F), U+0085, U+2028, U+2029, and the backslash itself, so a literal backslash-n and a real newline do not render identically. This closes the reported line whatever formatter the application turns out to be configured with - do not assume a JSON sink already covers this, since Serilog's own JSON formatters do not escape past the ASCII control range
- Fix every sink in that file, not only the reported one - a `catch` block or a leftover `Console.WriteLine`/`Trace.WriteLine` still interpolating keeps the finding live
- Replace interpolation with a message template - `logger.LogInformation("User {Username} logged in", username)`. On its own this neutralizes nothing: it separates template from value so an encoding-aware sink *can* act, which is why it accompanies the encoding rather than replacing it
- As a separate, durable change, adopt structured logging with `Microsoft.Extensions.Logging` and a JSON formatter, or Serilog with JSON sinks. Do not offer this as the fix for one finding: it depends on the sinks the application already has, and it reformats every line it emits
- Test by attempting to inject newlines, null bytes, and Unicode line separators - verify proper encoding
