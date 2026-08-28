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
- `requests.get(url)` re-resolves the hostname when it connects, so validation of an earlier lookup does not bind the connection; pin the checked address (a custom adapter or `CURLOPT_RESOLVE`-equivalent) or accept the residual rebinding risk explicitly

## Taint Sinks

`requests.get()`, `requests.post()`, `urllib.request.urlopen()`, `httpx.get()`

## Remediation Steps

- Parse and validate the URL scheme - reject anything other than `https://`
- Extract the hostname and resolve all A/AAAA records with `socket.getaddrinfo()`
- Check every resolved IP against blocked ranges using `ipaddress.ip_address()` and `is_global`
- Verify the hostname matches an allowlist of permitted domains
- Make the request with redirects disabled (`allow_redirects=False`)
- Set short timeouts to prevent resource exhaustion
