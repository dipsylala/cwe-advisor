# CWE-918: Server-Side Request Forgery (SSRF)

## LLM Guidance

Server-Side Request Forgery (SSRF) occurs when an application fetches remote resources based on user-supplied URLs without proper validation, allowing attackers to force the server to make requests to arbitrary destinations including internal services and cloud metadata endpoints. The vulnerability exploits the server's trusted network position. Never allow untrusted input to determine outbound request destinations.

## Key Principles

- Use URL allowlists - Maintain explicit allowlists of permitted domains/IPs and validate full URLs (scheme, host, port, path) against them - reject anything not on the list
- Block private IP ranges - Prevent access to internal networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback (127.0.0.0/8), link-local (169.254.0.0/16), and metadata endpoints
- Perform DNS validation - Resolve URLs and check that resolved IPs don't point to internal resources
- Never use denylists - Attackers will bypass them; allowlists are the only effective approach
- Enforce network egress controls - Limit outbound connections at the infrastructure level
- Validate the resolved *address*, not the hostname string, and re-pin it for the connection: a name that resolved to a permitted address can resolve to a private one on the next lookup (DNS rebinding), so resolve once and connect to that address
- Runtime URL parsers disagree, which is why a string blocklist fails: Node normalizes `[::ffff:7f00:1]` and similar forms while Python and Go do not, so the host your check inspects is not always the host the client dials
- Handle redirects explicitly - follow none, or re-run the full address check on every hop - since a permitted host can redirect the client out of the allowlist after the check passed
- Constrain egress at the network as well: a deny rule covering link-local (169.254.0.0/16, including the cloud metadata endpoint), loopback, and RFC 1918 ranges catches what the application-level check misses

- Test both directions. An allowlist that blocks everything looks identical to a working one in a
  re-scan, so assert that a public address such as `8.8.8.8` still fetches alongside asserting that
  the metadata address does not. Over-blocking is the usual way these fixes get reverted
- Where the target runs on a cloud instance, enforcing IMDSv2 is the strongest available mitigation
  and sits outside the application: it requires a `PUT` to obtain a token before any metadata read, so
  an SSRF limited to `GET` without header control fails against it even where the code fix is
  imperfect

## Remediation Steps

- Locate SSRF vulnerabilities by tracing untrusted data flow from input sources to the HTTP client call that issues the outbound request - see the language-specific guidance's Taint Sinks for concrete function names
- Implement URL allowlists as primary defence - validate full URLs against permitted destinations before making requests
- Add IP validation by resolving URLs and blocking private/internal IP ranges
- Use safe URL parsing libraries to prevent bypasses via encoding or URL manipulation
- Apply defence-in-depth with network segmentation and egress filtering
- Test with various bypass techniques (DNS rebinding, redirects, alternate encodings)
