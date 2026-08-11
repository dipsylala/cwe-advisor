# CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection') - Python

## LLM Guidance

In Python, the common concrete case of general CRLF injection (as opposed to CWE-113's HTTP-header-specific case) is email header injection: untrusted input placed into an email subject, recipient, or custom header lets an attacker inject `\r\n`-delimited headers to add BCC recipients, forge the sender, or append a second message. The `email` package's `EmailMessage` object rejects or folds embedded newlines when headers are set through it, but building the raw message as a formatted string (`f"Subject: {user_input}\r\n\r\n{body}"`) and handing it to `smtplib.SMTP.sendmail()` bypasses that protection entirely, since `sendmail()` sends whatever raw string it is given. Always build the message with `email.message.EmailMessage` and let it construct the raw payload.

## Key Principles

- Never hand-build CRLF-delimited text for any line-oriented sink (mail header, HTTP header, log line, or other protocol command) by concatenating untrusted data into a raw string - use the sink's structured API instead
- For mail, build the message with `email.message.EmailMessage` (or `email.mime.text.MIMEText`) and set headers via item assignment (`msg['Subject'] = value`), not by formatting a raw message string
- For HTTP response headers, use Flask's/Django's redirect and header helpers, which validate values - see CWE-113's Python guidance for depth
- For log statements, use structured (JSON) logging, or explicitly encode `\r`/`\n` before writing to a plain-text log - see CWE-117's guidance for depth
- Strip or reject `\r` and `\n` from untrusted input as defense in depth, regardless of sink, even when using `EmailMessage`
- Validate recipient/sender addresses with `email.utils.parseaddr()`/`getaddresses()` before use, since a crafted display name can also carry CRLF

## Taint Sinks

`smtplib.SMTP.sendmail()` fed a raw formatted message string, raw-concatenated email header assignment (not `EmailMessage`), `response.headers[...] =` with unsanitized input, `logging.info()`/`logger.warning()` with unsanitized input, raw text written to a `socket` for any line-oriented protocol

## Remediation Steps

- Identify the sink category - determine whether untrusted data reaches a mail header, an HTTP response header, a log statement, or a raw line-oriented protocol write (see Taint Sinks above)
- For mail headers - replace raw string-formatted message construction with `email.message.EmailMessage`, setting headers via item assignment, and send it via `smtplib.send_message()` rather than a hand-built string
- For HTTP response headers - see CWE-113's Python guidance for the framework-specific safe pattern
- For log statements - use structured (JSON) logging, or strip/encode `\r`/`\n` before writing to a plain-text log; see CWE-117's guidance for depth
- For any other line-oriented protocol - never hand-roll protocol commands by string concatenation with untrusted data; use a library that constructs and validates the protocol message, or strip/encode CRLF before writing to the socket
- Strip `\r` and `\n` from untrusted input as defense in depth, regardless of sink category
- Test with a payload containing `\r\nBcc: attacker@evil.com` (mail) or `\r\nX-Injected: true` (other sinks) and confirm no extra header or line is added

## Safe Pattern

```python
from email.message import EmailMessage
import smtplib

msg = EmailMessage()
msg['Subject'] = user_supplied_subject  # header folding/validation applied
msg['From'] = 'noreply@example.com'
msg['To'] = recipient_email
msg.set_content(user_supplied_body)

with smtplib.SMTP('smtp.example.com') as server:
    server.send_message(msg)  # sends the validated message object, not a raw string
```
