# CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')

## LLM Guidance

CRLF Injection occurs when untrusted input is written into any line-oriented, CRLF-delimited protocol or text format without neutralizing the carriage-return/line-feed sequence, letting an attacker inject additional lines, fields, or commands that the receiving parser interprets as new protocol elements. This spans mail header injection (SMTP), log forging, arbitrary line-based protocol commands, and other CRLF-delimited formats generally - for the HTTP-header-specific case (response splitting via `Location`/`Set-Cookie`/custom headers), see CWE-113. The core issue is allowing untrusted data to inject CRLF or protocol delimiters into structured, line-oriented text.

## Key Principles

- Never allow untrusted data to directly inject CRLF sequences or protocol delimiters
- Validate and encode all user input before generating structured, line-oriented text (mail headers, log entries, protocol commands)
- Trace data flow from untrusted sources to the point where the line-oriented text is constructed
- Prefer framework or library APIs that construct the protocol message for you over manual string concatenation
- Remove or encode CR (`\r`) and LF (`\n`) characters from all untrusted input

## Remediation Steps

- Identify the vulnerability - Review flaw details for file, line number, and code pattern where untrusted data reaches the construction of a line-oriented protocol message or log entry
- Trace data flow - Map the path from source (user input, database, external file) to the sink where the message, header, or log line is built
- Locate dangerous patterns - Find string concatenation or interpolation where untrusted data is inserted into a line that will be CRLF-delimited from the next
- Encode CRLF characters - Strip or encode `\r` and `\n` characters from all untrusted input before use
- Use safe APIs - Replace manual message construction with library or framework methods that handle encoding automatically
- Validate input - Implement allowlists for expected values and reject inputs containing control characters
