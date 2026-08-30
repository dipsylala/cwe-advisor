# CWE-601: URL Redirection to Untrusted Site ('Open Redirect') - Python

## LLM Guidance

Open redirect vulnerabilities occur when user-controlled input determines redirect destinations without validation, enabling phishing and credential theft. `urlparse().netloc == ''` is not sufficient on its own to prove a value is a safe relative path: `https:/evil.com`, `https:evil.com`, `///evil.com`, and `////evil.com` all parse to an empty `netloc` in Python, but a browser's URL parser tolerates a missing or extra slash after the scheme and resolves every one of them to host `evil.com`. A safe check has to validate the raw string's shape as well as the parsed fields, or require both scheme and host together for an absolute destination rather than trusting either alone.

## Key Principles

- Treat a value as a safe relative path only if the raw string starts with exactly one `/` (the second character is neither `/` nor `\`) and has no `:` before that leading `/` - this rejects the scheme-prefixed and multi-slash bypasses above without relying on `urlparse` to classify them correctly
- For an intentionally absolute redirect, require both `scheme` in `{"http", "https"}` and `netloc` matching the allowlist exactly - never accept one without the other, since an unchecked host behind a validated scheme (or the reverse) is exactly the gap the bypasses above exploit
- Django's `url_has_allowed_host_and_scheme()` is an internal function, not public API - a Django core developer has stated plainly not to use it directly, since it covers only part of the job and carries no stability guarantee across releases; read it as a reference implementation rather than import it as a dependency
- Flask and FastAPI have no framework-provided equivalent - implement the two-part check above directly using `urllib.parse`
- Prefer an indirect reference over parsing at all where the destinations are known ahead of time: map a short server-defined key to each allowed target and look it up, rather than validating an arbitrary URL
- Reading `parsed.port` on a malformed or attacker-crafted value can raise `ValueError` - guard it, or a redirect target designed to fail validation instead crashes the request with a 500
- Passing `settings.ALLOWED_HOSTS` as the allowlist for `url_has_allowed_host_and_scheme()` inherits any wildcard entry (`.example.com`) meant for multi-subdomain routing, silently widening the redirect allowlist to every subdomain
- A Pydantic `HttpUrl`/`AnyUrl` type annotation validates that a FastAPI parameter is a well-formed URL, not that its host is trusted - it accepts `https://evil.com` as readily as an internal path

## Taint Sinks

Flask `redirect()`, Django `HttpResponseRedirect()` / `redirect()`, FastAPI `RedirectResponse()` called with unvalidated input

## Remediation Steps

- Parse the redirect target with `urllib.parse.urlparse()`, but do not trust `netloc` alone to prove a value is relative - inspect the raw string too. `urljoin(request.host_url, next_url)` does not restrict anything: if `next_url` is already an absolute external URL, `urljoin` returns it essentially unchanged
- Accept a value as a safe relative path only when it starts with a single `/` (not two, and not `/\`) and has no `:` before that leading `/`
- For an absolute destination, require both an `http`/`https` scheme and a `netloc` present in your allowlist - reject if either check fails rather than falling through to a default-safe branch
- Django's `url_has_allowed_host_and_scheme()` implements this logic but is internal, unversioned API - treat it as a model to copy rather than a dependency; Flask and FastAPI need the check implemented directly
- Set a default safe redirect (e.g., `/dashboard`) when validation fails
- Test against `https:/evil.com`, `https:evil.com`, `///evil.com`, and `////evil.com`, not just the classic `//evil.com` case - each of the first four passes a `netloc == ''` check while a browser still redirects to `evil.com`
