# CWE-117: Improper Output Neutralization for Logs - Java

## LLM Guidance

Log Injection occurs when untrusted data is written to log files without encoding, allowing attackers to forge log entries or inject malicious content. The core fix is to use structured logging (JSON/ECS format) with SLF4J/Logback or Log4j2, which automatically encodes control characters within field values, preventing log forgery. Parameterized logging alone is insufficient without structured output formats.

## Key Principles

- Use structured logging formats (JSON, ECS) that encode control characters automatically within field boundaries
- Employ parameterized logging with SLF4J `{}` placeholders to separate untrusted data from log messages
- If structured logging is unavailable, encode ALL control characters: ASCII controls (0x00-0x1F), DEL (0x7F), C1 controls (0x80-0x9F), and Unicode line separators (U+0085, U+2028, U+2029)
- Avoid string concatenation when building log messages with user-controlled data
- Configure logstash-logback-encoder or Log4j2 JsonLayout for production environments

## Taint Sinks

`logger.info()`/`log.warn()` with string concatenation, `System.out.println()` with raw input

## Remediation Steps

- Encode the value at the call site before logging it: escape the ASCII control range (0x00-0x1F, 0x7F), U+0085, U+2028, U+2029, and the backslash itself as `\uXXXX`-style escapes, so a literal backslash-n and a real newline do not render identically. This closes the reported line in the file the finding names, whatever the application's logging configuration turns out to be
- Fix every sink in that file, not only the reported one - a `catch` block or a leftover `logger.debug()` still building its message by concatenation keeps the finding live
- Replace concatenation with SLF4J `{}` placeholders, keeping any `Throwable` as the trailing argument. On its own this neutralizes nothing: it separates template from value so an encoding-aware sink *can* act, which is why it accompanies the encoding rather than replacing it
- As a separate, durable change, move the application to structured logging - add logstash-logback-encoder or log4j-layout-template-json and configure the JSON encoder/layout in `logback.xml` or `log4j2.xml`. Do not offer this as the fix for one finding: it depends on which binding is actually on the classpath, needs a pinned version rather than a placeholder, and reformats every line the application emits
- Test by attempting to inject newlines, null bytes, and Unicode line separators into logged fields and verify proper encoding
