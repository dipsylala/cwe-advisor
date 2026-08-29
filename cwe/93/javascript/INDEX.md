# CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection') - JavaScript

## LLM Guidance

In Node.js, the common concrete case of general CRLF injection (as opposed to CWE-113's HTTP-header-specific case) is email header injection: untrusted input placed into a mail library's subject, recipient, or custom headers. Nodemailer does not reject a CR or LF - it replaces each with a space and carries on - so the payload does not become a second header, but it is not neutral either. The fix is to validate the value before it reaches the library and to pin a current version, not to rely on the library to refuse.

## Key Principles

- **A CRLF in a recipient field is still an attack after Nodemailer sanitizes it.** `_normalizeAddress` turns `victim@example.test\r\nBcc: attacker@evil.test` into `victim@example.test Bcc: attacker@evil.test`, which the address parser reads as RFC 5322 group syntax - the legitimate recipient drops out and the attacker's address becomes the *only* envelope recipient. Reject a CR or LF in an address rather than passing it through
- Nodemailer strips rather than rejects everywhere: header keys and values have CR/LF replaced with a space, and other control characters dropped. The one genuine rejection is at the SMTP envelope layer, which reports `EENVELOPE` through the callback - and it is unreachable for the case above, since normalization has already run
- Pin the version. The header-neutralization advisories are real but mostly carry no CVE id: `envelope.size` (fixed **8.0.4**), transport `name` (**8.0.5**), and `list.*.comment` (**8.0.9**) are the CWE-93 ones, CVE-2021-23400 covers newlines in an address object (**6.6.1**), and a further round of control-character fixes landed in **9.0.5**. Nodemailer backports nothing - its security policy is that fixes ship only against the latest major - so the floor is the current release
- Know which options escape the sanitizing entirely: `prepared: true` on a custom header writes `key + ': ' + value` verbatim, and `raw` supplies a whole pre-built MIME message. Neither is validated
- Set structured fields through the dedicated options (`to`, `cc`, `bcc`, `subject`), never through the `headers` option - the vendor documents those header names as reserved for the dedicated properties
- For HTTP response headers, use framework header-setting methods - see CWE-113's JavaScript guidance for depth. The CR/LF rejection there belongs to Node's `res.setHeader`, which throws `ERR_INVALID_CHAR`; Express and Koa reach it directly, while Fastify buffers headers and throws later, during send rather than at the call site
- For log statements, use structured (JSON) logging, or explicitly encode `\r`/`\n` before writing to a plain-text log - see CWE-117's guidance for depth
- Strip or reject `\r` and `\n` from untrusted input as defense in depth, regardless of sink

## Taint Sinks

`mailOptions.to`/`.cc`/`.bcc`/`.subject`, `mailOptions.headers` with `prepared: true`, `mailOptions.raw`, `mailOptions.list.*.comment`, `mailOptions.envelope`, transport `name`, `res.setHeader()`/`res.set()`, raw text written to a `net.Socket`

## Remediation Steps

- Identify the sink category - determine whether untrusted data reaches a mail field, an HTTP response header, a log statement, or a raw line-oriented protocol write (see Taint Sinks above)
- For mail fields - validate before the library sees the value: reject any address or subject containing CR or LF rather than letting the library collapse it, and pass values through the structured options object
- Check the manifest as well as the call site, against the floors above
- For HTTP response headers - see CWE-113's JavaScript guidance for the framework-specific safe pattern
- For log statements - use structured (JSON) logging, or strip/encode `\r`/`\n` before writing to a plain-text log; see CWE-117's guidance for depth
- For any other line-oriented protocol - never hand-roll protocol commands by string concatenation with untrusted data; use a library that constructs and validates the protocol message, or strip/encode CRLF before writing to the socket
- Test - send `\r\nBcc: attacker@evil.com` in a recipient field and **assert on the resolved envelope**, not on the header block. Checking only that no extra header appeared is the failing test here: it passes while the envelope has been rewritten to the attacker's address alone
