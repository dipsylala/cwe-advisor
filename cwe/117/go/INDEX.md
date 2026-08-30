# CWE-117: Improper Output Neutralization for Logs - Go

## LLM Guidance

Log injection in Go typically comes from `log.Printf`/`log.Println` writing untrusted data with embedded newlines, carriage returns, or ANSI escape sequences directly into a message string, or from legacy `log` package calls left behind after other call sites migrated to structured logging. The fix is moving the value from the message string to a structured `log/slog` attribute (Go 1.21+): the zero-value default, `NewTextHandler`, and `NewJSONHandler` all escape the ASCII control range (including newlines and ESC) in an attribute's value, so the injection fix does not depend on choosing a JSON handler. The two escapers still differ on Unicode line separators: `TextHandler`/default quote any non-printable rune, so U+0085/U+2028/U+2029 all get escaped, while `JSONHandler` inherits `encoding/json`'s behavior of specially escaping U+2028/U+2029 (its default HTML-safe mode) but passing U+0085 through raw, matching the general JSON-encoder gap this entry's other languages also carry.

## Key Principles

- Pass untrusted data as structured attributes (`slog.String("user", input)`), never concatenated into the message string - this alone closes an injection finding, because `slog` escapes ASCII control characters in attribute values under every handler, not only a JSON one
- `JSONHandler` leaves U+0085 unescaped even though it special-cases U+2028/U+2029; `TextHandler`/the default handler escape all three via printable-rune quoting - not a gap in ordinary newline/control-byte forging, but relevant if the finding specifically names a Unicode line separator
- Migrate every call site, not just the main path - background jobs and error branches left on the legacy `log` package remain unsanitized, since `log.Printf`/`log.Println` have no equivalent escaping
- Use `slog.NewJSONHandler` (or `logrus`/`zap` JSON formatters) as a durable, separate change for structured, machine-parseable output - do not present it as required to close a single finding, since a plain-text `slog` handler already escapes the same attribute values
- A custom `slog.Handler` written for a proprietary log shipper does not inherit this escaping automatically - it must implement its own before formatting output
- Where the field format is well-defined (username, ID), validate with a regex allowlist and log only the validated value as an additional layer

## Taint Sinks

`log.Printf()`, `log.Println()` with concatenated input, `slog.Info()`/`Error()` called with input baked into the message string instead of an attribute

## Remediation Steps

- Locate - find logging sinks: `log.Printf`, `log.Println`, `slog.Info`/`Error`, `logrus`/`zap` calls
- Trace data flow - identify request, header, or form data reaching a log call
- Fix the reported line - convert `log.Printf("...%s...", input)` to a structured `slog` call with the value passed as a typed attribute (`slog.String("user", input)`). This closes the finding under whichever handler is already configured, including the zero-value default
- Fix every sink in the file, not only the reported one - an error-handling branch or a background job left on `log.Printf` remains unsanitized, since the legacy `log` package has no equivalent escaping
- Break taint after allowlist validation - where format is well-defined, validate with a regex allowlist and log only the validated value
- As a separate, durable change, standardize on `slog.NewJSONHandler` (or `logrus.JSONFormatter`/`zap.NewProduction`) for machine-parseable output across every logger instance. Do not offer this as the fix for one finding: the injection safety comes from using structured attributes, not from the handler's output format
- Test - inject `\n`, `\r\n`, and ANSI escape sequences (`\x1b[2J`) into a logged attribute and confirm the entry shows an escaped sequence rather than a raw control byte, under the handler already in use
