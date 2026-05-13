# CWE-918: Server-Side Request Forgery (SSRF) - C\#

## LLM Guidance

Server-Side Request Forgery (SSRF) allows attackers to make the server perform HTTP requests to arbitrary destinations, potentially accessing internal services, cloud metadata endpoints (169.254.169.254), or bypassing firewalls.

**Primary Defence:** Validate URLs against an allowlist of permitted domains/IPs, block private/reserved IPv4 and IPv6 ranges, and use `AllowAutoRedirect = false` to prevent redirect-based bypasses.

## Key Principles

- Validate all URLs against an allowlist of permitted domains before making requests
- Block private, loopback, link-local, multicast, any-local, IPv4-mapped IPv6, and cloud metadata address ranges
- Disable automatic redirects with `AllowAutoRedirect = false` to prevent redirect-based SSRF bypasses
- Resolve DNS and validate resulting IP addresses to prevent DNS rebinding attacks
- Enforce HTTPS-only and implement request timeouts to prevent DoS

## Remediation Steps

- Create a URL validator that checks URLs against an allowlist of allowed domains/schemes
- Implement IP range checks covering both IPv4 and IPv6 private/reserved ranges
- Use `Dns.GetHostAddresses()` to resolve and validate IPs after initial URL validation
- Configure HttpClient with `AllowAutoRedirect = false` and `UseProxy = false`
- Block cloud metadata endpoints (169.254.169.254, metadata.google.internal) explicitly
- Return generic error messages to prevent information disclosure during validation failures

## Safe Pattern

```csharp
private static readonly HashSet<string> AllowedHosts = new() 
    { "api.example.com", "cdn.example.com" };

private Uri ValidateUrl(string url)
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri) || 
        uri.Scheme != "https" || !AllowedHosts.Contains(uri.Host.ToLowerInvariant()))
        throw new SecurityException("Invalid URL");
    
    foreach (var addr in Dns.GetHostAddresses(uri.Host))
    {
        if (!IsGlobalAddress(addr))
            throw new SecurityException("Private IP blocked");
    }
    return uri;
}

private static bool IsGlobalAddress(IPAddress address)
{
    if (address.IsIPv4MappedToIPv6)
        address = address.MapToIPv4();
    if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) ||
        address.Equals(IPAddress.IPv6Any) || address.IsIPv6LinkLocal ||
        address.IsIPv6Multicast)
        return false;

    var bytes = address.GetAddressBytes();
    if (address.AddressFamily == AddressFamily.InterNetwork)
        return !(bytes[0] == 10 || bytes[0] == 127 ||
                 (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                 (bytes[0] == 192 && bytes[1] == 168) ||
                 (bytes[0] == 169 && bytes[1] == 254));

    // Unique local fc00::/7
    return (bytes[0] & 0xfe) != 0xfc;
}
```
