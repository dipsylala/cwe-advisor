# CWE-601: URL Redirection to Untrusted Site ('Open Redirect') - Go

## LLM Guidance

Open redirects in Go occur when a value from `r.URL.Query().Get("next")`, `r.FormValue("redirect")`, or the `Referer` header is passed directly into `http.Redirect(w, r, target, status)` without validation. `http.Redirect` applies only minimal sanitization - it percent-encodes non-ASCII characters and resolves a relative path against the request path - and performs no validation of scheme or host, so that is the caller's responsibility. The primary fix is to validate the target against an allowlist-either a strict same-site path check (must start with `/`, not `//`, no backslashes, no scheme/host after `url.Parse`) or an explicit allowlist of external hostnames-and to use the allowlist-selected value, not the raw parameter, at the `http.Redirect` call.

## Key Principles

- Never pass a raw query parameter, form value, or `Referer`/`Origin` header directly into `http.Redirect`
- For same-site redirects, require the target to start with `/`, reject one starting with `//`, and confirm via `url.Parse` that `Scheme` and `Host` are both empty. Test for `\` as a separate string check rather than through the parse: Go does not treat a backslash as a path separator, so `/\evil.com` parses with an empty `Scheme` and `Host` and passes the check above, while a browser may still read it as protocol-relative
- For external redirects, maintain an explicit map or slice of allowed hostnames and compare `url.Parse(target).Hostname()` for an exact match, never `strings.Contains` or `strings.HasPrefix` on the raw URL string
- Checking `url.Parse(target).Host != ""` alone is insufficient-also check `Scheme != ""`, since an opaque URI like `javascript:alert(1)` parses with an empty `Host` but a non-empty `Scheme`
- For OAuth/SAML `redirect_uri` parameters, require an exact `==` match against a per-client registered URI list, never partial or substring matching. A registered URI is not a secret, so a constant-time comparison adds nothing here - reserve `subtle.ConstantTimeCompare` for values where a timing leak actually matters
- Apply the same validator function at every redirect entry point (login, logout, OAuth callback, any secondary API/mobile handler), not just the primary login flow

## Taint Sinks

`http.Redirect()` called with an unvalidated `r.URL.Query().Get()`, `r.FormValue()`, or `Referer` header value

## Remediation Steps

- Locate - Find every `http.Redirect(w, r, target, ...)` call and trace `target` back to its source: query parameter, form value, header, or session data
- Trace data flow - Confirm whether `target` passes through any validation before reaching `http.Redirect`; check for secondary paths (referrer-based redirects, separate reverse-proxy-aware handlers) that bypass the primary validator
- Replace the unsafe pattern - Introduce a single `isValidRedirectPath` or `isAllowedRedirectURL` function and route every redirect target through it before use
- Bind, encode, validate, or authorize - Parse the target with `url.Parse`, reject non-empty `Scheme`/`Host` for same-site redirects, or check `Hostname()` against an allowlist map for external redirects
- Break taint after allowlist validation - Assign the validated value to a fresh variable (or use the canonical value returned by `url.Parse`) and pass that, not the original request parameter, into `http.Redirect`
- Harden configuration - Default to a safe fallback path (e.g. `/home`) when validation fails, and return a 400 error for external-redirect endpoints when the target does not match the allowlist
- Test - Verify `//evil.com`, `https://trusted.com.evil.com`, `javascript:alert(1)`, and backslash-based paths are all rejected, while legitimate relative paths and allowlisted domains succeed
