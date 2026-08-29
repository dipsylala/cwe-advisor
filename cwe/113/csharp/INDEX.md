# CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting') - C#

## LLM Guidance

HTTP Response Splitting occurs when attackers inject CRLF (`\r\n`) characters into HTTP headers, enabling them to inject additional headers or response bodies, potentially leading to cache poisoning, XSS, or session hijacking. The vulnerability arises when user input is directly concatenated into HTTP headers without sanitization. ASP.NET Core rejects CR and LF at header assignment, so the live risks are the open redirect the rejection says nothing about, and the paths where that check is not present.

## Key Principles

- ASP.NET Core rejects CR, LF and other control characters in a header value with `InvalidOperationException` ("Invalid non-ASCII or control character in header"), thrown at the assignment, not at write time. So an unvalidated value is a 500 rather than a split response - a denial of service to fix, not a control to rely on
- That check belongs to the server's header collection, not to ASP.NET Core generally. Kestrel rejects everything above 0x7E, so it also stops U+0085/U+2028/U+2029; IIS in-process and HTTP.sys use the extended rule and allow those; and a plain `HeaderDictionary` (TestServer, a custom feature, a layer that rebuilds headers) performs no character check at all. Bytes written to `Response.Body` bypass all of it
- **`Redirect()` and `RedirectToAction()` do not sanitize the destination.** `RedirectResultExecutor` calls `IsLocalUrl` only to expand a `~/` prefix and passes a non-local URL through unchanged - so validate the target against an allowlist separately, since the framework's CR/LF rejection says nothing about where the redirect points
- `Url.IsLocalUrl()` is the vendor's open-redirect guard and is stricter than a `startsWith("/")` check: it rejects `//evil.example`, `/\evil.example`, and any ASCII control character including CR, LF and U+0085. It does accept U+2028 and U+2029, which are not `char.IsControl`. In minimal APIs the equivalent is `RedirectHttpResult.IsLocalUrl(url)` (.NET 10+)
- `Response.Cookies.Append()` percent-encodes the value with `Uri.EscapeDataString`, so CR/LF become `%0D%0A` rather than throwing, and it validates the cookie name. `CookieOptions.HttpOnly`, `Secure` and `SameSite` all default to off, so set them explicitly
- Build a `Content-Disposition` with `ContentDispositionHeaderValue.SetHttpFileName()`, which sets both `FileName` and `FileNameStar` using HTTP encodings and emits the RFC 5987 form. Assigning `.FileName` directly encodes as a MIME encoded-word instead, which is the wrong grammar for an HTTP header
- Reject rather than strip, and do not filter percent-encoded forms. `%0d` in a header value is three literal characters that cannot split a response; the .NET Framework's own header defence *produces* `%0d`/`%0a` as its safe output, so removing that sequence deletes the encoded-safe form and mangles any legitimate value containing it

## Taint Sinks

`Response.Headers.Add()`/`Append()`, `Response.Headers["Location"]`, `Response.Redirect()`, `Results.Redirect()`, `Response.ContentType`, `Response.AppendTrailer()`

## Remediation Steps

- Locate the sink and confirm which server is in play, since the character check differs between Kestrel, IIS in-process and a bare `HeaderDictionary`
- Use `Redirect()` or `RedirectToAction()` instead of setting the `Location` header manually, and validate the destination with `Url.IsLocalUrl()` for local redirects or an explicit allowed-origin allowlist for external ones
- Prefer `Response.Headers.Append(...)` or the indexer over `Headers.Add()`, which throws on a duplicate key (analyzer ASP0019)
- Validate the value against an allowlist of the characters that header's grammar permits, anchored with `\z` rather than `$`, and reject a value that fails rather than editing it
- Use `Response.Cookies.Append()` with `HttpOnly`, `Secure` and `SameSite` set explicitly, rather than composing a `Set-Cookie` string
- For a download filename, call `SetHttpFileName()`. Reach for `UrlEncoder.Default.Encode()` only on a value that is genuinely a URL *component*: applied to a whole URL it returns `%2Faccount%3Fx%3D1`, which the browser resolves as a relative path, so every legitimate redirect breaks while every malicious-input test still passes - a rejected value never reaches the encoder. The assertion that catches it is following an accepted redirect to its destination
- Note that `Response.AddHeader()` exists only on .NET Framework's `System.Web.HttpResponse`; on ASP.NET Core the equivalents are the `Response.Headers` APIs above. There is no header-validation switch to enable - `enableHeaderChecking` is a `<system.web>` setting that ASP.NET Core does not read
