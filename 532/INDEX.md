# CWE-532: Insertion of Sensitive Information into Log File

## LLM Guidance

Sensitive information in log files occurs when applications write confidential data (passwords, tokens, PII, session IDs) to application logs, system logs, or debug output. Logs are often stored with weak access controls, retained for long periods, backed up to multiple locations, and aggregated to centralized logging systems - multiplying exposure risk.

Common examples include authentication failures logging passwords, request/response logging containing sensitive data, error messages with credentials, debug output, database query logs, and API interaction logs containing tokens or payment information.

## Key Principles

- Never log passwords, tokens, API keys, session IDs, PII, credit cards, or health data
- Redact sensitive data at the source before it reaches logging infrastructure
- Log generic messages with identifiers, not actual sensitive values
- Treat all logs as potentially exposed; assume attackers will access them
- Use structured logging with automatic sanitization for known sensitive fields
- Redact at the logging layer with a field-name filter that recurses through nested objects and lists, so a call site that forgets to sanitize still fails safe - that is the common case, and per-call-site discipline is what a fix built on it depends on
- The strongest fix is not passing the secret to the logger at all; redaction is what covers the structured-payload case where the whole object must be logged
- A log entry outlives its request by the retention period rather than the session, and is readable by support staff, on-call engineers, the aggregation service, and whatever ships the logs there - a much larger set of people than could read the credential where it was stored

## Remediation Steps

- Review flaw details to identify what sensitive data is being logged and locate the logging statement
- Identify log sources - authentication logging, request/response logging, error handlers, debug output
- Trace logging calls (`logger.info()`, `console.log()`, `syslog()`, framework loggers) to find where sensitive data enters
- Filter sensitive data before logging - replace passwords/tokens with "[REDACTED]" or omit entirely
- Log generic messages with non-sensitive identifiers - "Login attempt - user=X" not "password=Y"
- Sanitize request/response logging to exclude headers (Authorization, Cookie) and body fields with sensitive data
