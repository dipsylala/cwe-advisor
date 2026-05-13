# CWE-93: CRLF Injection - Java

## LLM Guidance

CRLF Injection occurs when attackers inject `\r\n` characters to manipulate HTTP headers, log files, or line-based formats, potentially enabling HTTP response splitting or log forgery. The core fix is to strip or reject newline characters (`\r`, `\n`, `\r\n`) from all user input before using it in HTTP headers or logs. Use framework header APIs as defense in depth, but still validate header values explicitly.

## Key Principles

- Input Sanitization: Remove or reject all CR/LF characters from user-controlled data before using in headers or logs
- Framework Protection: Use Spring's `HttpHeaders` and `ResponseEntity` with explicit CR/LF validation
- Structured Logging: Use JSON/ECS structured logging or encode CR/LF before writing to plain-text logs
- Allowlist Validation: Validate header values against strict patterns (alphanumeric, specific safe characters only)
- Avoid Direct Manipulation: Never directly construct HTTP headers or log entries from untrusted input

## Remediation Steps

- Identify all locations where user input flows into HTTP headers or log statements
- Replace direct header manipulation with Spring's `HttpHeaders` API
- Sanitize input by removing `\r` and `\n` characters - `value.replaceAll("[\\r\\n]", "")`
- Implement regex validation for expected header value formats before use
- Convert log statements to structured logging or encode control characters before parameterized plain-text logging
- Test with CRLF payloads (`%0d%0a`, `\r\n`) to verify protection

## Safe Pattern

```java
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

public ResponseEntity<String> setCustomHeader(String userInput) {
    // Sanitize input - remove CRLF characters
    String sanitized = userInput.replaceAll("[\\r\\n]", "");
    
    // Use Spring's HttpHeaders after explicit validation
    HttpHeaders headers = new HttpHeaders();
    headers.add("X-Custom-Header", sanitized);
    
    return ResponseEntity.ok()
        .headers(headers)
        .body("Response");
}
```
