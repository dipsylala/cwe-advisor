# CWE-642: External Control of Critical State Data

## LLM Guidance

This weakness occurs when security- or business-critical state - a role, permission flag, price, or session attribute - is stored somewhere the client can read or write, such as a cookie, hidden form field, query parameter, or local storage, and the server trusts that value without independent verification. The source is client-supplied input; the sink is a security or business decision that branches directly on it. The fix is to keep critical state server-side, in a session store keyed by an opaque identifier, or to recompute and verify the value against an authoritative server record before acting on it.

## Key Principles

- Never make a security or business decision by reading a value directly from client-controlled storage: cookie, hidden field, parameter, or local storage
- Store authoritative state server-side, keyed by an opaque session identifier the client cannot meaningfully alter
- When a client-supplied value legitimately affects a decision (product ID, quantity), recompute the sensitive part (price, permission) from server data instead of accepting it as sent
- If state must travel with the client, protect it with a server-verified signature or encryption and a short expiry, and reject anything that fails verification before parsing its contents
- Ignore unexpected privileged fields in client requests (role, is_admin) rather than applying them if present
- Apply this at every trust boundary crossing: request bodies, query strings, cookies, and any client-writable storage

## Remediation Steps

- Locate - identify the source: a cookie, hidden field, query or body parameter, or local/session storage value the client can set
- Trace data flow - follow the value to its sink: an authorization check, price calculation, or other security or business decision
- Identify the unsafe pattern - the sink trusts the client-supplied value directly, with no server-side authoritative check
- Replace with the safe pattern - read the security-relevant value from server-side session state, or recompute and verify it against the server's own record
- If client-side state is unavoidable, sign or encrypt it server-side and verify the signature on every use before trusting any field inside it
- Add secondary controls - reject or ignore unexpected privileged fields in incoming requests rather than applying them
- Test - tamper with the relevant cookie, field, parameter, or token and confirm the server rejects or ignores it and uses the authoritative server value instead
