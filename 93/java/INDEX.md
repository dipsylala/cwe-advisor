# CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection') - Java

## LLM Guidance

In Java, the common concrete case of general CRLF injection (as opposed to CWE-113's HTTP-header-specific case) is email header injection through the JavaMail API: untrusted input placed into a `MimeMessage`'s subject, recipient, or custom headers lets an attacker inject `\r\n`-delimited headers to add BCC recipients, forge the sender, or append a second message. `InternetAddress` and `MimeMessage.setSubject()` apply MIME encoding when used correctly, but `MimeMessage.addHeader(name, value)` and raw SMTP socket writes do not neutralize embedded CRLF on their own. Always build addresses through `InternetAddress` and encode any user-controlled header text, never concatenate it into a raw header string.

## Key Principles

- Never hand-build CRLF-delimited text for any line-oriented sink (mail header, HTTP header, log line, or other protocol command) by concatenating untrusted data into a raw string - use the sink's structured/typed API instead
- For mail, build addresses with `InternetAddress`, which validates and encodes the address, and set the subject via `MimeMessage.setSubject(value, charset)` rather than a raw header string
- For HTTP response headers, use Spring's `HttpHeaders`/`ResponseEntity` APIs with explicit validation - see CWE-113's Java guidance for depth
- For log statements, use structured (JSON/ECS) logging, or explicitly encode `\r`/`\n` before writing to a plain-text log - see CWE-117's guidance for depth
- Strip or reject `\r` and `\n` from untrusted input as defense in depth, regardless of sink
- Validate display names and free-text fields separately from the address itself, since a crafted display name can also carry CRLF

## Taint Sinks

`MimeMessage.addHeader()`/`setHeader()`/`setSubject()` from raw concatenation, `new InternetAddress(rawString, false)` with validation disabled, `HttpServletResponse.setHeader()`/`addHeader()` with unsanitized input, `Logger.info()`/`log.warn()` with unsanitized input, raw text written to a `Socket`/`OutputStream` for any line-oriented protocol

## Remediation Steps

- Identify the sink category - determine whether untrusted data reaches a mail header, an HTTP response header, a log statement, or a raw line-oriented protocol write (see Taint Sinks above)
- For mail headers - replace raw string concatenation with `MimeMessage.setSubject()`/`setRecipients()` and `InternetAddress` construction; avoid `new InternetAddress(value, false)` (validation disabled)
- For HTTP response headers - see CWE-113's Java guidance for the framework-specific safe pattern
- For log statements - use structured (JSON/ECS) logging, or strip/encode `\r`/`\n` before writing to a plain-text log; see CWE-117's guidance for depth
- For any other line-oriented protocol - never hand-roll protocol commands by string concatenation with untrusted data; use a library that constructs and validates the protocol message, or strip/encode CRLF before writing to the stream
- Strip `\r` and `\n` from untrusted input as defense in depth, regardless of sink category
- Test with a payload containing `\r\nBcc: attacker@evil.com` (mail) or `\r\nX-Injected: true` (other sinks) and confirm no extra header or line is added

## Safe Pattern

```java
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

MimeMessage message = new MimeMessage(session);
message.setFrom(new InternetAddress("noreply@example.com"));
message.setRecipient(Message.RecipientType.TO, new InternetAddress(recipientEmail)); // validates, throws on malformed input

// Strip CRLF as defense in depth before the value ever reaches setSubject()
String safeSubject = userSuppliedSubject.replaceAll("[\r\n]", "");
message.setSubject(safeSubject, "UTF-8"); // MIME-encodes remaining content
message.setText(userSuppliedBody);

Transport.send(message);
```
