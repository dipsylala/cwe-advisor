# CWE-472: External Control of Assumed-Immutable Web Parameter

## LLM Guidance

A Base-level child of CWE-642 and usually the better fit for it: a web parameter the application assumes cannot have changed - a hidden field, a cookie, a disabled input, a query string. Where the value is a configuration setting instead, use CWE-15.

## Key Principles

- Never trust client-side data as immutable - always validate server-side
- Recompute critical values (prices, permissions, quotas) from authoritative sources
- Store authoritative state server-side (sessions, databases), not in client parameters
- Validate all inputs even if marked "disabled" or "hidden" in UI
- Use cryptographic signatures or HMACs for parameters that must round-trip to client
- Recompute the value server-side rather than validating what the client returned: a price, a total, a discount, or a role read back from a hidden field is client state whatever the form said
- Where the tampered parameter is an *identifier* and the missing control is an ownership check, the finding is CWE-639; this entry is a *value* the server acts on directly
- A disabled input, a hidden field, and a cookie are all the same channel from the server's point of view - the browser is not a trust boundary

## Remediation Steps

- Locate vulnerabilities - Review data paths where client-controlled parameters affect pricing, authorization, or business logic without server-side validation
- Identify assumed-immutable fields - Find hidden inputs, cookies, URL parameters, disabled form fields used as trusted data
- Implement server-side validation - Verify all client-supplied values against authoritative server-side sources
- Recompute critical values - Calculate prices, quotas, and permissions from database/session data, not client parameters
- Use secure tokens - For parameters requiring client storage, apply cryptographic signatures (HMAC) to detect tampering
- Apply defence-in-depth - Combine server-side validation with session management and access controls
