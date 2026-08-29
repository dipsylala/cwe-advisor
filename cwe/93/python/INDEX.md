# CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection') - Python

## LLM Guidance

In Python, the common concrete case of general CRLF injection (as opposed to CWE-113's HTTP-header-specific case) is email header injection: untrusted input placed into an email subject, recipient, or custom header. Which protection you actually get depends on the *policy* the message carries and on the interpreter version, and building the raw message as a formatted string (`f"Subject: {user_input}\r\n\r\n{body}"`) and handing it to `smtplib.SMTP.sendmail()` bypasses all of it - `sendmail` not only skips validation, it normalizes lone newlines up into full CRLF on the way out.

## Key Principles

- **`EmailMessage` rejects; it does not fold.** Under `email.policy.default` - which `EmailMessage()` uses when no policy is given - assigning a header containing CR or LF raises `ValueError` at the assignment. That is the protection to rely on
- **`MIMEText` and `Message` are not equivalent.** They default to the legacy `compat32` policy, which stores the injected value verbatim and fails only later, at serialization, with `HeaderWriteError` - and that backstop (`verify_generated_headers`) is the CVE-2024-6923 fix, so it exists only from **3.8.20 / 3.9.20 / 3.10.15 / 3.11.10 / 3.12.5 / 3.13**. On an older interpreter there is no check at all on that path. Prefer `EmailMessage`, and pass `policy=email.policy.default` if you must use the MIME classes
- Build the message with `email.message.EmailMessage` and set headers via item assignment (`msg['Subject'] = value`), then send with `SMTP.send_message()` rather than a hand-built string. `send_message` validates nothing itself - its safety is that it serializes through `BytesGenerator`, which is where the check above fires
- **`parseaddr()` is not a CRLF validator, and the display name is exactly where it fails.** Given `Real\r\nName <a@b.com>` it collapses the newline to a space and returns success. It signals a malformed address only by returning `('', '')`, which is easy to miss. Its `strict=True` default arrived in **3.13** (backported to 3.8.20+) for CVE-2023-27043; with `strict=False` a crafted address returns a plausible but wrong result
- Reject `\r` and `\n` at your own boundary rather than relying on any of the above to do it, and validate with a whole-string match (`re.fullmatch()`), since `$` in Python's `re` also matches before a trailing newline and `^...$` therefore admits the exact character being excluded
- `smtplib` guards its own commands: `putcmd` raises `ValueError` for CR or LF, from **3.6.15 / 3.7.12 / 3.8.12 / 3.9.7 / 3.10**. That covers the envelope addresses `sendmail` builds, and nothing in `msg` - the DATA payload never passes through it
- For HTTP response headers, see CWE-113's Python guidance for depth. Note the two checks there are separate layers: Django's `BadHeaderError` is its own, while `h11`'s `LocalProtocolError` covers ASGI servers such as uvicorn and hypercorn - a WSGI app under gunicorn has neither
- For log statements, use structured (JSON) logging, or explicitly encode `\r`/`\n` before writing to a plain-text log - see CWE-117's guidance for depth

## Taint Sinks

`smtplib.SMTP.sendmail()` fed a raw formatted message string, header assignment on a `compat32` message (`MIMEText`, `Message`), `email.utils.parseaddr()` used as a validator, `response.headers[...] =`, `logging.info()`/`logger.warning()` with unsanitized input, raw text written to a `socket`

## Remediation Steps

- Identify the sink category - determine whether untrusted data reaches a mail header, an HTTP response header, a log statement, or a raw line-oriented protocol write (see Taint Sinks above)
- For mail headers - replace raw string-formatted message construction with `email.message.EmailMessage`, set headers via item assignment, and send with `SMTP.send_message()`
- Confirm the policy in play, since it is what performs the check, and the interpreter version against the floors above
- Validate addresses at your own boundary - reject CR and LF explicitly rather than inferring validity from `parseaddr()` returning something
- For HTTP response headers - see CWE-113's Python guidance for the framework-specific safe pattern
- For log statements - use structured (JSON) logging, or strip/encode `\r`/`\n` before writing to a plain-text log; see CWE-117's guidance for depth
- For any other line-oriented protocol - never hand-roll protocol commands by string concatenation with untrusted data; use a library that constructs and validates the protocol message, or strip/encode CRLF before writing to the socket
- Test - submit `\r\nBcc: attacker@evil.com` in a subject and in an address, and assert the request is rejected at your validation boundary; also assert the resolved recipient list, since a value that survives parsing can change who receives the message without adding a visible header
