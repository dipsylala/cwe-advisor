# CWE-918: Server-Side Request Forgery (SSRF) - Java

## LLM Guidance

SSRF occurs when attackers manipulate server-side requests to access internal resources, cloud metadata endpoints, or bypass network controls. Core fix: validate URLs against allowlists of permitted domains, block private IP ranges (RFC 1918, loopback, link-local), and restrict protocols to HTTPS only.

**Primary Defence:** Validate URLs against an allowlist of permitted domains/IPs, block private IP ranges (RFC 1918, loopback, link-local), and restrict protocols to `https://` only.

## Key Principles

- Validate all URLs against allowlists of permitted domains/IPs before making requests
- Block private, loopback, link-local, multicast, and cloud metadata address ranges using `InetAddress` checks
- Restrict protocols to HTTPS only to prevent file:// or jar:// exploits
- Implement DNS resolution checks to detect rebinding attacks
- Use network-level protections and egress filtering

## Remediation Steps

- Create an allowlist of permitted domains/hosts for outbound requests
- Parse and validate URLs before making requests, checking scheme and host
- Resolve all host A/AAAA records and check if any resolved IP is in a blocked range
- Reject URLs targeting private IPs, localhost, cloud metadata endpoints (169.254.169.254)
- Configure HttpClient with strict redirect and timeout policies (disable redirects if possible)
- Log all outbound requests for monitoring and incident response

## Safe Pattern

```java
private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com", "cdn.example.com");

public String fetchUrl(String urlString) throws Exception {
    URL url = new URL(urlString);
    if (!ALLOWED_HOSTS.contains(url.getHost())) {
        throw new SecurityException("Host not allowed");
    }
    if (!"https".equals(url.getProtocol())) {
        throw new SecurityException("Only HTTPS allowed");
    }
    for (InetAddress addr : InetAddress.getAllByName(url.getHost())) {
        if (addr.isLoopbackAddress() || addr.isLinkLocalAddress() ||
            addr.isSiteLocalAddress() || addr.isAnyLocalAddress() ||
            addr.isMulticastAddress()) {
            throw new SecurityException("Private IP blocked");
        }
    }

    HttpClient client = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();
    // Pair DNS validation with egress firewall rules to prevent second-resolution bypasses.
    return client.send(HttpRequest.newBuilder(url.toURI()).build(), 
           HttpResponse.BodyHandlers.ofString()).body();
}
```
