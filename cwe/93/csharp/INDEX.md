# CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection') - C#

## LLM Guidance

In C#, the common concrete case of general CRLF injection (as opposed to CWE-113's HTTP-header-specific case) is email header injection: untrusted input placed into an email's subject, recipient, or custom header fields lets an attacker inject additional `\r\n`-delimited headers. `System.Net.Mail` neutralizes more of this than it is usually credited with - but the coverage is uneven and version-dependent, and Microsoft steers new development away from the namespace entirely. Populate mail headers through the typed `MailMessage` properties, never build a raw SMTP payload by string concatenation, and check the runtime version.

## Key Principles

- **Microsoft does not recommend `SmtpClient` for new development** - its own remarks say so and point to MailKit, because `SmtpClient` "doesn't support many modern protocols". It is not marked obsolete, so it keeps compiling; MailKit/MimeKit is the maintained alternative for new code
- `MailMessage.Subject` has always rejected an embedded CR or LF, throwing `ArgumentException`. That is the strongest guarantee in the namespace, and it is undocumented - the property page has no exceptions section at all
- **The recipient properties are the version-dependent part.** Address parsing did not reject CR/LF until a 2026 change, and two spoofing advisories bracket it: CVE-2026-32178 (floor **8.0.26 / 9.0.15 / 10.0.6**) and CVE-2026-50659, an SMTP-smuggling fix in the CRLF encoding of the body stream (floor **8.0.29 / 9.0.18 / 10.0.10**). .NET 6 is out of support and receives neither
- A custom header added via `MailMessage.Headers` is checked less than it looks at add time - only the header *name* is validated - but at send time `EncodeHeaders` RFC 2047-encodes any value containing CR or LF rather than emitting it raw. So the classic `\r\nBcc:` payload through `Headers.Add` is encoded, not injected, on a current runtime. Do not use that payload as the proof your fix works
- Validate addresses by constructing a `MailAddress`, which throws `FormatException` on a malformed value - but note the documentation explicitly says the two-argument constructor "does not check if the `displayName` parameter is valid", so the display name is the part to validate yourself
- Never hand-build CRLF-delimited text for any line-oriented sink (mail header, HTTP header, log line, or other protocol command) by concatenating untrusted data into a raw string - use the sink's structured/typed API instead
- For HTTP response headers, use ASP.NET Core's header and cookie APIs - see CWE-113's C# guidance for depth, including which server actually performs the character check
- For log statements, structured logging helps only if the provider emits structured output: the default console formatter writes plain text and does not encode newlines, so name `AddJsonConsole()` or an equivalent sink rather than `ILogger` alone. See CWE-117's guidance for depth

## Taint Sinks

`MailMessage.Headers.Add()`, `MailMessage.To`/`.Bcc`/`.CC` built from raw strings, `MailMessage.ReplyToList`, `Response.Headers.Add()` (ASP.NET Core) / `Response.AppendHeader()` (.NET Framework), `ILogger.LogInformation()` with unsanitized input, raw text via `NetworkStream.Write()`/`StreamWriter.WriteLine()`

## Remediation Steps

- Identify the sink category - determine whether untrusted data reaches a mail header, an HTTP response header, a log statement, or a raw line-oriented protocol write (see Taint Sinks above)
- For mail headers - populate `MailMessage`'s typed properties, construct recipients as `MailAddress` objects, and validate the display name separately
- Check the runtime against the floors above before treating recipient handling as safe, and prefer MailKit/MimeKit for new code
- For HTTP response headers - see CWE-113's C# guidance for the framework-specific safe pattern
- For log statements - configure a structured (JSON) logging provider, or strip/encode `\r`/`\n` before writing to a plain-text log; see CWE-117's guidance for depth
- For any other line-oriented protocol - never hand-roll protocol commands by string concatenation with untrusted data; use a library that constructs and validates the protocol message, or strip/encode CRLF before writing to the stream
- Test - reject a subject or address containing `\r\n` at your own validation boundary and assert the rejection there. A payload that only checks whether an extra header appeared passes on a current runtime whether or not your validation exists
