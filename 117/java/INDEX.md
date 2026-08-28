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

- Add logstash-logback-encoder or log4j-layout-template-json dependency to your project
- Configure Logback/Log4j2 to use JSON encoder/layout in logback.xml or log4j2.xml
- Replace string concatenation in log statements with parameterized logging using `{}`
- Pass user input as parameters, not concatenated into the message string
- For legacy systems without JSON support, encode control characters as backslash escapes (`\r`, `\n`, `\t`, and `\\` for the backslash itself) with a `\uXXXX` fallback for the rest, so a literal backslash-n and a real newline do not render identically
- Test by attempting to inject newlines, null bytes, and Unicode line separators into logged fields and verify proper encoding
