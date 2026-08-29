# CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection') - Java

## LLM Guidance

In Java, CWE-77 commonly appears where an application drives an SMTP (or IMAP/FTP) control-channel dialogue by writing raw protocol commands to a `Socket` instead of using a maintained mail/protocol client. This is distinct from CWE-78 (`ProcessBuilder`/`Runtime.exec` OS execution), covered separately. The primary defence is to let a library such as Jakarta Mail carry the SMTP command dialogue, rather than concatenating untrusted input into command lines sent over the socket - with the version floor below, because the library did not always reject the injection itself.

## Key Principles

- **Primary defence:** use Jakarta Mail's `Session`/`Transport` API (`Transport.send(message)`) instead of opening a `Socket` to the SMTP port and writing `MAIL FROM:`/`RCPT TO:`/`DATA` command lines by hand
- Never build an SMTP (or IMAP/FTP) command line by concatenating untrusted input (an address, a filename) into a string terminated with `\r\n`; an embedded CRLF lets the input inject an additional protocol command into the same connection
- **Version floor, and it is the point of the fix:** the transport itself concatenates - `SMTPTransport` builds `"MAIL FROM:" + normalizeAddress(from)`, and `normalizeAddress` only adds angle brackets. A CR/LF scan on the outgoing command was added for CVE-2025-7962 and first ships in `org.eclipse.angus:smtp` **2.0.4**, `com.sun.mail:jakarta.mail` **2.0.2** and **1.6.8**. Below those, an address that survives parsing reaches the socket intact. Pin the *implementation* artifact - upgrading `jakarta.mail:jakarta.mail-api` alone does not pick the fix up
- What stops the injection below that floor is `InternetAddress` parsing, and it is narrower than it looks: CR/LF in an *unquoted* local part is rejected, but a CRLF followed by a space or tab inside a quoted string is allowed by design
- Message headers are outside all of this. `MimeMessage.setSubject`'s javadoc puts the duty on the caller - "The application must ensure that the subject does not contain any line breaks" - and the same holds for `setHeader`/`addHeader`. The command-channel scan does not cover anything inside DATA
- Validate with `new InternetAddress(address, true)`. Do not also call `validate()` expecting a second check: both run the same `checkAddress(addr, true, true)`, and neither returns a value - failure arrives as `AddressException`, so it has to be caught rather than tested as a boolean. Construction alone is not a check, since the one-argument constructor skips those additional syntax checks
- Apply the same principle to any other hand-rolled protocol client (IMAP, FTP): prefer a maintained client library over raw socket text
- Log rejected or malformed addresses for monitoring, without echoing raw untrusted input back into any interpreter

## Taint Sinks

`Socket.getOutputStream().write()` with hand-built SMTP/IMAP/FTP command lines (concatenated `\r\n`)

## Remediation Steps

- Locate - find code that opens a `Socket` to an SMTP/IMAP/FTP port and writes command strings built via concatenation or `String.format`
- Trace data flow - identify which fields (recipient address, filename, subject, custom headers) come from untrusted input and reach the command string or the message
- Replace with the safe pattern - switch to Jakarta Mail's `Session`/`Transport`/`MimeMessage` API (or the equivalent maintained client library for IMAP/FTP)
- Check the version before treating the library as the fix - below the floor above, the transport forwards CR/LF that address parsing let through
- Validate as defence-in-depth - build with `new InternetAddress(address, true)` inside a try/catch, rejecting on `AddressException`
- Break taint - use only the validated `InternetAddress` object for the sink, not the original raw string; strip CR and LF from any value written into a header
- Harden configuration - `mail.smtp.starttls.enable=true` is opportunistic and continues in plaintext when the server does not advertise STARTTLS, so set `mail.smtp.starttls.required=true` (JavaMail 1.4.2+) to fail instead, configure a trust store, and authenticate with least-privilege credentials
- Test - submit addresses containing `\r\n` followed by extra SMTP commands, and a subject containing `\r\n`, and confirm each is rejected rather than forwarded to the server
