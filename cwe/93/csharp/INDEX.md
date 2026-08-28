# CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection') - C#

## LLM Guidance

In C#, the common concrete case of general CRLF injection (as opposed to CWE-113's HTTP-header-specific case) is email header injection: untrusted input placed into an email's subject, recipient, or custom header fields lets an attacker inject additional `\r\n`-delimited headers - adding BCC recipients, forging the From address, or appending a second message body. `System.Net.Mail.MailMessage`'s typed properties reject embedded CRLF, but custom headers added via `MailMessage.Headers` or any raw SMTP command construction bypass that protection. Always populate mail headers through the typed `MailMessage` properties and never build a raw SMTP payload by string concatenation.

## Key Principles

- Never hand-build CRLF-delimited text for any line-oriented sink (mail header, HTTP header, log line, or other protocol command) by concatenating untrusted data into a raw string - use the sink's structured/typed API instead
- For mail, populate headers through `MailMessage`'s typed properties (`Subject`, `To`, `Bcc`) and validate addresses via `MailAddress` construction rather than raw strings
- For HTTP response headers, use ASP.NET's built-in header/cookie APIs, which validate values - see CWE-113's C# guidance for depth
- For log statements, use structured (JSON) logging via `ILogger`, or explicitly encode `\r`/`\n` before writing to a plain-text log - see CWE-117's guidance for depth
- Strip or reject `\r`, `\n`, and their percent-encoded forms (`%0d`, `%0a`) from untrusted input as defense in depth, regardless of sink
- Keep the mail library and its dependencies current, since header-neutralization behavior has been hardened in past releases

## Taint Sinks

`MailMessage.Headers.Add()`/`.Subject`/`.To`/`.Bcc` from raw concatenation, `Response.Headers.Add()`/`AppendHeader()` with unsanitized input, `ILogger.LogInformation()`/`LogWarning()` etc. with unsanitized input, raw text written via `NetworkStream.Write()`/`StreamWriter.WriteLine()` for any line-oriented protocol

## Remediation Steps

- Identify the sink category - determine whether untrusted data reaches a mail header, an HTTP response header, a log statement, or a raw line-oriented protocol write (see Taint Sinks above)
- For mail headers - replace raw string concatenation with `MailMessage`'s typed properties (`Subject`, `To`, `Bcc`), and validate addresses via `MailAddress` construction, which throws on malformed input, instead of a raw string
- For HTTP response headers - see CWE-113's C# guidance for the framework-specific safe pattern
- For log statements - use structured (JSON) logging, or strip/encode `\r`/`\n` before writing to a plain-text log; see CWE-117's guidance for depth
- For any other line-oriented protocol - never hand-roll protocol commands by string concatenation with untrusted data; use a library that constructs and validates the protocol message, or strip/encode CRLF before writing to the stream
- Strip `\r`, `\n`, and their percent-encoded forms (`%0d`, `%0a`) from untrusted input as defense in depth, regardless of sink category
- Test with a payload containing `\r\nBcc: attacker@evil.com` (mail) or `\r\nX-Injected: true` (other sinks) and confirm no extra header or line is added
