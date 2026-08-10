# CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection') - Java

## LLM Guidance

In Java, CWE-77 commonly appears where an application drives an SMTP (or IMAP/FTP) control-channel dialogue by writing raw protocol commands to a `Socket` instead of using a maintained mail/protocol client. This is distinct from CWE-78 (`ProcessBuilder`/`Runtime.exec` OS execution), covered separately. The primary defence is to let a library such as Jakarta Mail frame the SMTP command dialogue, rather than concatenating untrusted input into command lines sent over the socket.

## Key Principles

- **Primary defence:** use Jakarta Mail's `Session`/`Transport` API (`Transport.send(message)`) instead of opening a `Socket` to the SMTP port and writing `MAIL FROM:`/`RCPT TO:`/`DATA` command lines by hand
- Never build an SMTP (or IMAP/FTP) command line by concatenating untrusted input (an address, a filename) into a string terminated with `\r\n`; an embedded CRLF lets the input inject an additional protocol command into the same connection
- `Transport`/`Session` construct `InternetAddress` values and frame each protocol command internally, so untrusted data placed into an address field cannot be interpreted as a new SMTP verb
- Validate addresses with `InternetAddress.validate()` before use, as defence-in-depth on top of the library's own framing
- Apply the same principle to any other hand-rolled protocol client (IMAP, FTP): prefer a maintained client library over raw socket text
- Log rejected or malformed addresses for monitoring, without echoing raw untrusted input back into any interpreter

## Remediation Steps

- Locate - find code that opens a `Socket` to an SMTP/IMAP/FTP port and writes command strings built via concatenation or `String.format`
- Trace data flow - identify which fields (recipient address, filename) come from untrusted input and reach the command string
- Replace with the safe pattern - switch to Jakarta Mail's `Session`/`Transport`/`MimeMessage` API (or the equivalent maintained client library for IMAP/FTP)
- Validate as defence-in-depth - call `InternetAddress.validate()` on address fields and reject values that fail validation before constructing the message, on top of the framing `Transport`/`Session` already provide
- Break taint - use only the validated `InternetAddress` object for the sink, not the original raw string
- Harden configuration - configure the mail session over TLS (`mail.smtp.starttls.enable=true`) and authenticate with least-privilege credentials
- Test - submit addresses containing `\r\n` followed by extra SMTP commands and confirm the library rejects them rather than forwarding them to the server

## Safe Pattern

```java
import jakarta.mail.*;
import jakarta.mail.internet.*;
import java.util.Properties;

// SAFE: Transport frames the SMTP dialogue; InternetAddress validates the envelope address
Properties props = new Properties();
props.put("mail.smtp.host", "smtp.example.com");
props.put("mail.smtp.starttls.enable", "true");
Session session = Session.getInstance(props);

InternetAddress to = new InternetAddress(untrustedRecipient);
to.validate(); // throws AddressException on malformed input

MimeMessage message = new MimeMessage(session);
message.setRecipient(Message.RecipientType.TO, to);
message.setSubject(untrustedSubject); // subject content goes into the MIME message, not the SMTP command channel
message.setText(body);

Transport.send(message);
```
