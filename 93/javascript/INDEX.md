# CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection') - JavaScript

## LLM Guidance

In Node.js, the common concrete case of general CRLF injection (as opposed to CWE-113's HTTP-header-specific case) is email header injection: untrusted input placed into a mail library's subject, recipient, or custom headers lets an attacker inject `\r\n`-delimited headers to add BCC recipients, forge the sender, or append a second message. Modern versions of Nodemailer reject control characters in address and subject fields, but older versions, custom headers passed through unvalidated, or any hand-rolled SMTP command construction over a raw socket do not get that protection. Always pass mail fields through the library's structured options object and keep the mail dependency current, never build a raw SMTP payload by string concatenation.

## Key Principles

- Never hand-build CRLF-delimited text for any line-oriented sink (mail field, HTTP header, log line, or other protocol command) by concatenating untrusted data into a raw string - use the sink's structured API instead
- For mail, pass subject, recipient, and body values through the mail library's structured options (`to`, `cc`, `bcc`, `subject`) rather than a raw message string
- For HTTP response headers, use framework header-setting methods (e.g. Express `res.set()`) that validate or reject control characters - see CWE-113's JavaScript guidance for depth
- For log statements, use structured (JSON) logging, or explicitly encode `\r`/`\n` before writing to a plain-text log - see CWE-117's guidance for depth
- Strip or reject `\r` and `\n` from untrusted input as defense in depth, regardless of sink
- Keep the mail library (e.g. Nodemailer) at a current version, since header-neutralization behavior has been hardened in past releases after real CVEs

## Taint Sinks

`mailOptions.to`/`.cc`/`.bcc`/`.subject` from raw concatenation, mail library custom-headers option with unsanitized input, `res.setHeader()`/`res.set()` with unsanitized input, `console.log()`/logger calls with unsanitized input, raw text written to a `net.Socket` for any line-oriented protocol

## Remediation Steps

- Identify the sink category - determine whether untrusted data reaches a mail field, an HTTP response header, a log statement, or a raw line-oriented protocol write (see Taint Sinks above)
- For mail fields - pass values through the mail library's structured options object (`to`, `cc`, `bcc`, `subject`) rather than building a raw message string, and confirm the library version is current
- For HTTP response headers - see CWE-113's JavaScript guidance for the framework-specific safe pattern
- For log statements - use structured (JSON) logging, or strip/encode `\r`/`\n` before writing to a plain-text log; see CWE-117's guidance for depth
- For any other line-oriented protocol - never hand-roll protocol commands by string concatenation with untrusted data; use a library that constructs and validates the protocol message, or strip/encode CRLF before writing to the socket
- Strip `\r` and `\n` from untrusted input as defense in depth, regardless of sink category
- Test with a payload containing `\r\nBcc: attacker@evil.com` (mail) or `\r\nX-Injected: true` (other sinks) and confirm no extra header or line is added

## Safe Pattern

```javascript
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({ host: 'smtp.example.com' });

await transporter.sendMail({
  from: 'noreply@example.com',
  to: recipientEmail,           // library validates/rejects embedded CRLF
  subject: userSuppliedSubject, // library validates/rejects embedded CRLF
  text: userSuppliedBody,
});
```
