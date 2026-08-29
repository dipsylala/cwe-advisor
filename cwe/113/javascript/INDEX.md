# CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting') - JavaScript

## LLM Guidance

HTTP Response Splitting in Node.js occurs when user-supplied values are passed to `res.setHeader()`, `res.redirect()`, or `res.cookie()` without validation. Node's `http` module has rejected CR and LF in header values since long before the CVE-2016-2216 hardening (that release fixed a Unicode-decomposition *bypass* of the existing check, and shipped in 0.10.42, 0.12.10, 4.3.0 and 5.6.0), so the classic literal-newline attack on `res.setHeader()`/`res.writeHead()` is closed and Express delegates to it. What remains open is the redirect *target*, and any value that reaches a header after a decode Node never sees.

## Key Principles

- Node rejects a bad header *name* with `ERR_INVALID_HTTP_TOKEN` and a bad *value* with `ERR_INVALID_CHAR`, so both surface as a 500 rather than a split response - fix the validation instead of relying on the throw, and note neither applies to bytes written directly to the socket
- The rejected set is "outside latin1", so U+2028 and U+2029 are rejected while **U+0085 is not** - it is latin1 `0x85` and passes through. It is also not a line terminator to an HTTP parser, so this is a reason not to treat the three as one group rather than a gap to plug
- **`res.redirect()` does not throw and does not validate.** Express routes it through `res.location()`, which percent-encodes via `encodeurl` - so CR/LF become `%0D%0A` and Node's check is never reached. Express documents this outright: the URL is passed to the browser "without any validation". `//evil.example/x`, `https://evil.example` and `javascript:alert(1)` all pass straight through
- So validate the destination separately. Express's own recommendation is to parse it - `new URL(input)` and compare `host` against an allowlist - not to match a character class. If you do write a path pattern, **anchor it**: `RegExp.test()` searches anywhere in the string, so an unanchored pattern accepts every payload above by matching a substring of it
- Use the framework's cookie API rather than composing a `Set-Cookie` string. `res.cookie()` encodes the value with `encodeURIComponent` by default and throws `TypeError` for an invalid cookie *name*; a hand-built header silently loses `Secure`, `HttpOnly` and `SameSite` along with the escaping
- Percent-encoded `%0d`/`%0a` are not decoded anywhere in Node or Express, so a header value containing them cannot split a response and filtering them out only corrupts legitimate values. They matter only where the application decodes again after validating
- `encodeURIComponent()` alone does not produce a valid RFC 5987 `filename*` value: it leaves `'`, `(`, `)` and `*` unescaped, and `'` is the ext-value delimiter itself. Escape those four as well, or use a library that emits the parameter
- Keep the dependencies current: CVE-2024-29041 was an open redirect in `res.location()` reached through `res.redirect()` (floor **Express 4.19.2** / 5.0.0-beta.3), and CVE-2024-47764 let a cookie *name* inject further attributes (floor **cookie 0.7.0**). `res.redirect('back')` is deprecated in Express 4 and removed in 5 - it is a referrer-driven open redirect

## Taint Sinks

`res.setHeader()`, `res.writeHead()`, `res.location()`, `res.redirect()`, `res.cookie()`, `res.append()`, `res.appendHeader()`, `res.addTrailers()`

## Remediation Steps

- Replace manual `res.setHeader('Location', userInput)` with `res.redirect()` after validating the destination
- Validate redirect URLs by parsing them and checking the host against an allowlist, or - for a local path - with a whole-string anchored pattern such as `/^\/(?!\/)[a-zA-Z0-9/_-]*$/`, which rejects `//evil.example` and `/\evil.example` where an unanchored one accepts both
- Validate any other header value against the characters that header's grammar permits, and reject rather than edit
- For `Content-Disposition`, emit `filename*=UTF-8''` with `encodeURIComponent` plus an escape for `!'()*`, keeping a plain ASCII `filename` as the fallback
- Use `res.cookie('name', value, { httpOnly: true, secure: true, sameSite: 'strict' })` instead of setting `Set-Cookie` manually
- Test by submitting `%0d%0aInjected-Header: evil` and a literal `\r\n` in redirect and cookie parameters, and separately submit `//evil.example` to confirm the open redirect is closed too - the CRLF test passes without it
