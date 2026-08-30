# CWE-117: Improper Output Neutralization for Logs - Java

## LLM Guidance

Log Injection occurs when untrusted data is written to log files without encoding, allowing attackers to forge log entries or inject malicious content. Encode at the call site to close a reported finding immediately; moving to structured JSON logging (`logstash-logback-encoder` for Logback, or `log4j-layout-template-json` for Log4j2) is a separate, durable improvement, not a substitute - both encoders escape the ASCII control range plus quote and backslash, but neither escapes DEL (0x7F) or the Unicode line separators (U+0085, U+2028, U+2029), so the manual encoding below is still needed even with JSON output configured. Parameterized logging (`{}` placeholders) alone encodes nothing.

## Key Principles

- Encode the value at the call site first: ASCII controls (0x00-0x1F), DEL (0x7F), U+0085, U+2028, U+2029, and the backslash itself. This closes the finding regardless of which logging backend is configured
- Employ parameterized logging with SLF4J `{}` placeholders to keep untrusted data out of the message template - `{}` is documented as positional substitution only and does not encode the substituted value, so this accompanies the encoding above rather than replacing it
- Structured logging (JSON, ECS) via `logstash-logback-encoder` or `log4j-layout-template-json` is a durable secondary control: both escape 0x00-0x1F and `"`/`\` automatically, but neither extends to DEL or the Unicode line separators
- Avoid string concatenation when building log messages with user-controlled data
- `org.apache.commons.text.StringEscapeUtils.escapeJava()` (Apache Commons Text) is a maintained alternative to hand-rolled escaping - it does encode the Unicode line separators but, like the JSON encoders above, does not encode DEL (0x7F)

## Taint Sinks

`logger.info()`/`log.warn()` with string concatenation, `System.out.println()` with raw input

## Remediation Steps

- Encode the value at the call site before logging it: escape the ASCII control range (0x00-0x1F, 0x7F), U+0085, U+2028, U+2029, and the backslash itself as `\uXXXX`-style escapes, so a literal backslash-n and a real newline do not render identically. This closes the reported line in the file the finding names, whatever the application's logging configuration turns out to be
- Fix every sink in that file, not only the reported one - a `catch` block or a leftover `logger.debug()` still building its message by concatenation keeps the finding live
- Replace concatenation with SLF4J `{}` placeholders, keeping any `Throwable` as the trailing argument. On its own this neutralizes nothing: it separates template from value so an encoding-aware sink *can* act, which is why it accompanies the encoding rather than replacing it
- As a separate, durable change, move the application to structured logging - add logstash-logback-encoder or log4j-layout-template-json and configure the JSON encoder/layout in `logback.xml` or `log4j2.xml`. Do not offer this as the fix for one finding: it depends on which binding is actually on the classpath, needs a pinned version rather than a placeholder, and reformats every line the application emits
- Test by attempting to inject newlines, null bytes, and Unicode line separators into logged fields and verify proper encoding
