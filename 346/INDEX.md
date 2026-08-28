# CWE-346: Origin Validation Error

## LLM Guidance

Origin validation errors occur when an application fails to properly verify the source of a request or message - accepting cross-origin requests without checking the Origin/Referer header, misconfiguring CORS to allow arbitrary or overly broad origins, trusting `postMessage()` senders without an origin check, or failing to re-validate a resolved DNS host (DNS rebinding). Left unchecked, this can enable CSRF (for which CWE-352's token-based defence is the primary fix), cross-origin data theft, or unauthorized cross-domain access. The core fix here is validating the origin of the request or message itself against a strict allowlist before trusting it - not adding a token-based defence, which addresses a different layer.

## Key Principles

- Validate the request/message origin against a strict allowlist of trusted origins before trusting it
- Configure CORS restrictively: enumerate explicit allowed origins rather than using a wildcard, and never combine a wildcard origin with credentialed requests
- Validate the origin of any cross-context message (`postMessage()` listeners, embedded iframes, browser extension messaging) before acting on its content
- Never trust a client-supplied Referer or Origin header as sole proof of legitimacy without a defined allowlist to check it against
- Guard against DNS rebinding by re-validating the resolved host/IP against expectations, not just the hostname string
- For the CSRF-specific consequence of a missing origin check, apply CWE-352's token-based defence as well - origin validation and CSRF tokens are complementary, not substitutes for each other
- Match the `Origin` header against an exact allowlist server-side and echo only that value - never a wildcard, the reflected header, or a suffix or substring match
- Never allowlist the literal `null` origin: an attacker can make a request carry `Origin: null` from a page they fully control (a sandboxed iframe, a `data:` URL, certain redirect chains), so `null` in the list admits anyone
- Send `Vary: Origin` with the response, or a shared cache can hand the response built for one allowed origin to a different one
- Route by the specific manifestation: forged state-changing requests riding a victim's session are CWE-352, and an over-broad `Access-Control-Allow-Origin`, `crossdomain.xml`, or `postMessage` handler is CWE-942

## Remediation Steps

- Identify missing origin checks - Review scan results for endpoints, message handlers, or CORS configuration accepting cross-origin input without validation
- Find vulnerable entry points - Locate `postMessage()` listeners, CORS-enabled endpoints, or request handlers that don't verify origin
- Fix CORS configuration - Replace a wildcard `Access-Control-Allow-Origin` with an explicit allowlist of trusted origins; never pair a wildcard with `Access-Control-Allow-Credentials: true`
- Validate Origin/Referer - Check the Origin header (preferred) or Referer header against the allowlist before processing the request
- Validate message-passing origins - In `postMessage()` listeners, check `event.origin` against an allowlist before trusting `event.data`
- Guard DNS-based checks - Where origin trust is based on hostname, re-verify the resolved address to prevent rebinding
- Test cross-origin scenarios - Attempt requests and messages from untrusted origins and confirm they are rejected
