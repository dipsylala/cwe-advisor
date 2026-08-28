# CWE-918: Server-Side Request Forgery (SSRF) - Python

## LLM Guidance

Server-Side Request Forgery (SSRF) allows attackers to make the server perform HTTP requests to arbitrary destinations, accessing internal services, cloud metadata endpoints (169.254.169.254), or bypassing firewall controls. Always validate URLs against an allowlist of permitted domains, block private/reserved IP ranges using the `ipaddress` module, and restrict protocols to `https://` only.

## Key Principles

- Validate all URLs against an explicit allowlist of permitted domains/hosts before making requests
- Block access to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16)
- Restrict protocols to `https://` only; deny `file://`, `gopher://`, `dict://`, and other dangerous schemes
- Use DNS resolution checks to prevent DNS rebinding attacks
- Disable HTTP redirects or validate redirect destinations
- Include the IPv6 ranges alongside the IPv4 ones - `::1`, `fc00::/7`, `fe80::/10` and the NAT64 prefix `64:ff9b::/96` - and use `ipaddress.ip_address()` classification rather than string prefixes
- `ipaddress`'s own classification was wrong before CPython 3.12.4 (CVE-2024-4032): `is_private` and `is_global` disagreed with the IANA special-purpose registries on several IPv4 and IPv6 ranges, so the check below silently misclassifies them on an unpatched interpreter. The fix was backported to the 3.8-3.11 branches; take the exact patch level from the advisory and confirm the runtime carries it, or test the ranges explicitly rather than relying on the property
- Handle the IPv6 spellings of an IPv4 address as the Java and JavaScript guidance does: `ipaddress` normalizes the mapped form `::ffff:127.0.0.1` via `ipv4_mapped`, but the compatible form `::7f00:1` and the NAT64 prefix are separate cases that a mapped-only check misses
- `requests.get(url)` re-resolves the hostname when it connects, so validation of an earlier lookup does not bind the connection; pin the checked address (a custom adapter or `CURLOPT_RESOLVE`-equivalent) or accept the residual rebinding risk explicitly

## Taint Sinks

`requests.get()`, `requests.post()`, `urllib.request.urlopen()`, `httpx.get()`

## Remediation Steps

- Parse and validate the URL scheme - reject anything other than `https://`
- Extract the hostname and resolve all A/AAAA records with `socket.getaddrinfo()`
- Check every resolved IP with `ipaddress.ip_address()`, but do not rest the decision on `is_global`
  alone: multicast addresses such as `224.0.0.1` and `ff02::1` report `is_global` as true, as does the
  NAT64 form `64:ff9b::7f00:1`, so test `is_multicast` and the NAT64 prefix explicitly alongside it
- Verify the hostname matches an allowlist of permitted domains
- Make the request with redirects disabled (`allow_redirects=False`)
- Set short timeouts to prevent resource exhaustion
