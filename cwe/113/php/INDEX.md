# CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting') - PHP

## LLM Guidance

HTTP Response Splitting in PHP occurs when user-supplied values are passed to `header()` without validation. PHP's engine rejects a header value containing CR or LF, but the manual documents none of this - the behaviour lives in `sapi_header_op` in php-src - and the rejection is narrower than it looks. Non-`header()` output paths (raw `fwrite` to the response stream, a SAPI-level write) do not get it at all. The live risks are the redirect *target*, which no character check addresses, and the trailing-newline case PHP silently accepts.

## Key Principles

- `header()` raises an `E_WARNING` ("Header may not contain more than a single header, new line detected") and drops the header. It returns `void` and the script continues, so nothing in the calling code can branch on the failure - the redirect simply never happens and a 200 with the page body goes out instead
- **Version floor: the 5.1.2 fix was LF-only.** A lone `\r` was not rejected until **PHP 5.3.11 / 5.4.0** (bug #60227), so on anything older the check is bypassable with a bare carriage return
- **Trailing CR or LF is silently trimmed rather than rejected**, because the whitespace strip runs before the safety check. `header("Location: /a\r\n")` sends `Location: /a` with no warning. Injection-shaped input is caught; a value whose only newline trails is quietly altered
- A NUL byte is rejected separately, with "Header may not contain NUL bytes"
- Do not filter percent-encoded `%0a`/`%0d` out of input. PHP decodes `$_GET`/`$_POST` before the script sees them, so an encoded payload arrives as literal CR LF and `header()` already rejects it; removing the three-character string only corrupts legitimate values such as a filename containing `%0a`
- Use `setcookie()` rather than `header('Set-Cookie: ...')`. It raw-url-encodes the value, so CR/LF become `%0D%0A`, and it throws `ValueError` for `=`, `,`, `;`, whitespace, CR or LF in the *name*, and for those characters in `path` and `domain`. `setrawcookie()` skips the encoding and throws on the value instead
- `session_set_cookie_params()` is a different weakness: CR/LF in `path` or `domain` are caught downstream and the whole session cookie is dropped, but `;` is not blocked at any layer, so a crafted `path` injects further cookie attributes
- `wp_safe_redirect()` allowlists **only the site's own host** by default, falling back to `admin_url()`; extend it through the `allowed_redirect_hosts` filter. It also does not exit on its own, so it needs a following `exit`
- Validate with `\A...\z` or the `D` modifier rather than `^...$`, since PCRE's `$` also matches before a trailing newline

## Taint Sinks

`header()`, `setrawcookie()`, `header_remove()` with a derived name, raw `fwrite`/`echo` to the response stream before headers flush

## Remediation Steps

- Locate `header('Location: ' . $var)` patterns where `$var` derives from user input
- Validate redirect URLs against an allowlist of permitted destinations, or confirm the value is a relative path from a known character class - the CR/LF rejection says nothing about where the redirect points
- Validate any other header value against the characters that header's grammar permits, anchored with `\A...\z`, and reject rather than edit
- Replace manual `header('Set-Cookie: ...')` construction with `setcookie()`, which encodes the value and validates the name, path and domain
- For `Content-Disposition`, emit RFC 5987 `filename*=UTF-8''` - `basename()` then `rawurlencode()`, whose output is a valid ext-value - and keep a plain ASCII `filename` alongside it, since older clients ignore `filename*`
- Check for a `header_register_callback` hook before concluding the output path is clean - it runs after your code has finished and can put attacker-controlled text back into a header you already validated
- Test with `%0d%0aX-Injected: evil` appended to redirect parameters, and separately with a value whose only newline is trailing, since that one is accepted rather than rejected
