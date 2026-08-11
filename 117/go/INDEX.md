# CWE-117: Improper Output Neutralization for Logs - Go

## LLM Guidance

Log injection in Go typically comes from `log.Printf`/`log.Println` writing untrusted data with embedded newlines, carriage returns, or ANSI escape sequences directly into text logs, or from legacy `log` package calls left behind after other call sites migrated to structured logging. The primary remediation is structured logging with Go 1.21+ `log/slog` (or `logrus`/`zap`) using a JSON handler, which encodes field values so control characters cannot break the log record or forge new entries.

## Key Principles

- Use `log/slog` with `slog.NewJSONHandler` (or `logrus`/`zap` JSON formatters) so field values are JSON-escaped automatically
- Pass untrusted data as structured attributes (`slog.String("user", input)`), never concatenated into the message string
- Migrate every call site, not just the main path - background jobs and error branches left on the legacy `log` package remain unsanitized
- If plain-text logging cannot be avoided, strip or encode all control characters (0x00-0x1F, 0x7F) and CR/LF using `strings.Map` with `unicode.IsControl`, not a partial newline-only replace
- A custom `slog.Handler` written for a proprietary log shipper does not inherit JSON escaping automatically - verify it encodes control characters itself before formatting output
- Where the field format is well-defined (username, ID), validate with a regex allowlist and log only the validated value as an additional layer

## Taint Sinks

`log.Printf()`, `log.Println()` with concatenated input, `slog.Info()`/`Error()` called with input baked into the message string instead of an attribute

## Remediation Steps

- Locate - find logging sinks: `log.Printf`, `log.Println`, `slog.Info`/`Error`, `logrus`/`zap` calls
- Trace data flow - identify request, header, or form data reaching a log call
- Replace the unsafe pattern - convert `log.Printf("...%s...", input)` to structured `slog` calls with input as a typed attribute
- Bind, encode, validate, or authorize - configure `slog.NewJSONHandler` (or `logrus.JSONFormatter`/`zap.NewProduction`) so attribute values are JSON-encoded
- Break taint after allowlist validation - where format is well-defined, validate with a regex allowlist and log only the validated value
- Harden configuration - ensure every logger instance in the codebase uses the JSON handler/formatter, not a mix of `slog.NewTextHandler` and the legacy `log` package
- Test - inject `\n`, `\r\n`, and ANSI escape sequences (`\x1b[2J`) into logged fields and confirm the entry stays on one JSON line with escaped output

## Safe Pattern

```go
// SAFE: structured logging with JSON handler escapes control characters
package main

import (
	"log/slog"
	"os"
)

var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

func logFailedLogin(username, ip string) {
	// SAFE: username is a structured attribute; slog JSON-escapes newlines/control chars
	logger.Info("failed login attempt",
		slog.String("username", username),
		slog.String("ip", ip),
	)
}
```
