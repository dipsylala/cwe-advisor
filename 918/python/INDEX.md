# CWE-918: Server-Side Request Forgery (SSRF) - Python

## LLM Guidance

Server-Side Request Forgery (SSRF) allows attackers to make the server perform HTTP requests to arbitrary destinations, accessing internal services, cloud metadata endpoints (169.254.169.254), or bypassing firewall controls. Always validate URLs against an allowlist of permitted domains, block private/reserved IP ranges using the `ipaddress` module, and restrict protocols to `https://` only.

## Key Principles

- Validate all URLs against an explicit allowlist of permitted domains/hosts before making requests
- Block access to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16)
- Restrict protocols to `https://` only; deny `file://`, `gopher://`, `dict://`, and other dangerous schemes
- Use DNS resolution checks to prevent DNS rebinding attacks
- Disable HTTP redirects or validate redirect destinations

## Remediation Steps

- Parse and validate the URL scheme - reject anything other than `https://`
- Extract the hostname and resolve all A/AAAA records
- Check every resolved IP against blocked ranges using `ipaddress.ip_address()` and `is_global`
- Verify the hostname matches an allowlist of permitted domains
- Make the request with redirects disabled (`allow_redirects=False`)
- Set short timeouts to prevent resource exhaustion

## Safe Pattern

```python
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_DOMAINS = {"api.trusted-service.com"}

def safe_request(url):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Only HTTPS allowed")
    if parsed.hostname not in ALLOWED_DOMAINS:
        raise ValueError("Domain not allowed")
    
    addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
    for _, _, _, _, sockaddr in addresses:
        ip_obj = ipaddress.ip_address(sockaddr[0])
        if not ip_obj.is_global:
            raise ValueError("Private IP blocked")
    
    # Pair DNS validation with egress firewall rules to prevent second-resolution bypasses.
    return requests.get(url, allow_redirects=False, timeout=5)
```
