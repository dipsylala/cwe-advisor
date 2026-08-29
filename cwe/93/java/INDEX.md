# CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection') - Java

## LLM Guidance

In Java, the common concrete case of general CRLF injection (as opposed to CWE-113's HTTP-header-specific case) is email header injection through Jakarta Mail: untrusted input placed into a `MimeMessage`'s subject, recipient, or custom headers lets an attacker inject `\r\n`-delimited headers to add BCC recipients, forge the sender, or append a second message. The library places this duty on the caller rather than taking it on, and its own transport did not reject an injected command until 2025 - so the fix is to validate the value yourself and to pin the implementation version.

## Key Principles

- **The javadoc puts the duty on you, in as many words.** `MimeMessage.setSubject` states "The application must ensure that the subject does not contain any line breaks", and the class documentation says callers of `setHeader`, `addHeader` and `addHeaderLine` "are responsible for enforcing the MIME requirements for the specified headers". There is no documented CR/LF rejection for any header value
- **Version floor on the transport.** CR/LF in an outgoing SMTP command was only rejected after CVE-2025-7962, which first ships in `org.eclipse.angus:smtp` **2.0.4** and `com.sun.mail:jakarta.mail` **2.0.2** and **1.6.8**. Pin the implementation artifact - upgrading `jakarta.mail:jakarta.mail-api` alone does not pick the fix up. Note the scan covers the command channel only, so headers inside DATA are still yours to validate
- What protects an address below that floor is `InternetAddress` parsing, and it is narrower than it looks: CR/LF in an *unquoted* local part is rejected, but a CRLF followed by a space or tab inside a quoted string is allowed by design
- Build addresses with `new InternetAddress(address, true)` and catch `AddressException`; `new InternetAddress(value, false)` disables the additional syntax checks, and the one-argument constructor is equivalent to `false`. Do not also call `validate()` expecting a second opinion - it runs the same check
- Validate display names and free-text fields separately from the address itself, since a crafted display name can also carry CRLF
- Never hand-build CRLF-delimited text for any line-oriented sink (mail header, HTTP header, log line, or other protocol command) by concatenating untrusted data into a raw string - use the sink's structured/typed API instead
- Write the newline check as `Pattern.compile("[\\r\\n]").matcher(value).find()`. The obvious `value.matches(".*[\\r\\n].*")` is wrong in a way that reads as right: `matches()` requires the whole string to match and `.` does not cross a line terminator, so it returns false for a value containing `\r\n` - catching a lone CR or LF and missing the pair. Adding `(?s)` fixes it if the `matches()` form has to stay
- Strip or reject `\r` and `\n` from untrusted input as defense in depth, regardless of sink
- For HTTP response headers, see CWE-113's Java guidance for depth - including that Spring Security's `FirewalledResponse` already rejects CR/LF on the servlet response sinks when a filter chain is present
- SLF4J's `{}` placeholders are not the log-forging fix on their own - they keep the template and the value apart, but Logback's default `PatternLayout` writes the resolved value into the line verbatim, so a `\r\n` in it forges an entry exactly as concatenation would. The layout or encoder has to escape it too; see CWE-117's guidance for depth

## Taint Sinks

`MimeMessage.addHeader()`/`setHeader()`/`addHeaderLine()`/`setSubject()`, `new InternetAddress(rawString, false)`, `InternetAddress(String, String)` with an unvalidated display name, `HttpServletResponse.setHeader()`/`addHeader()`, `Logger.info()`/`log.warn()` with unsanitized input, raw text written to a `Socket`/`OutputStream`

## Remediation Steps

- Identify the sink category - determine whether untrusted data reaches a mail header, an HTTP response header, a log statement, or a raw line-oriented protocol write (see Taint Sinks above)
- For mail headers - reject CR and LF at your own validation boundary before the value reaches `setSubject()` or a header setter, since the library does not do it for you
- Build recipients with `new InternetAddress(address, true)` inside a try/catch, and use only the resulting object at the sink
- Check the implementation artifact and version against the floor above
- For HTTP response headers - see CWE-113's Java guidance for the framework-specific safe pattern
- For log statements - use structured (JSON/ECS) logging, or strip/encode `\r`/`\n` before writing to a plain-text log; see CWE-117's guidance for depth
- For any other line-oriented protocol - never hand-roll protocol commands by string concatenation with untrusted data; use a library that constructs and validates the protocol message, or strip/encode CRLF before writing to the stream
- Test - submit `\r\nBcc: attacker@evil.com` in a subject, an address and a display name, and confirm each is rejected at your boundary rather than reaching the message
