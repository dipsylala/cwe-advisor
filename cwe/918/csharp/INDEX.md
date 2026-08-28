# CWE-918: Server-Side Request Forgery (SSRF) - C#

## LLM Guidance

Server-Side Request Forgery (SSRF) allows attackers to make the server perform HTTP requests to arbitrary destinations, potentially accessing internal services, cloud metadata endpoints (169.254.169.254), or bypassing firewalls.

**Primary Defence:** Validate URLs against an allowlist of permitted domains/IPs, block private/reserved IPv4 and IPv6 ranges, and use `AllowAutoRedirect = false` to prevent redirect-based bypasses.

## Key Principles

- Validate all URLs against an allowlist of permitted domains before making requests
- Block private, loopback, link-local, multicast, any-local, IPv4-mapped IPv6, and cloud metadata address ranges, unmapping with `MapToIPv4()` when `IsIPv4MappedToIPv6` is set so the range test sees the v4 address
- Disable automatic redirects with `AllowAutoRedirect = false`. State the reason plainly when fixing:
  the property defaults to `true`, so a validated host redirecting to an internal one is followed
  unless this is set. `MaxAutomaticRedirections` only caps how many hops are taken, not where they go
- Resolve DNS and validate resulting IP addresses to prevent DNS rebinding attacks
- Enforce HTTPS-only and implement request timeouts to prevent DoS
- Use `IsIPv6UniqueLocal` (.NET 6+) for `fc00::/7` - `IsIPv6SiteLocal` sounds like private IPv6 and matches only the deprecated `fec0::/10` - and write byte tests for `0.0.0.0/8`, `100.64.0.0/10` and `192.0.0.0/24`, which have no property at all
- Block the whole `169.254.0.0/16` range rather than the single AWS metadata address, which covers the Azure and Alibaba endpoints too
- Check every answer `Dns.GetHostAddresses()` returns, not the first
- Set `UseProxy = false`: validation established what the host resolves to from *this* process, and .NET opts into a proxy from the environment without being asked, which forwards the hostname to be resolved at the other end
- Close the rebinding race with `SocketsHttpHandler.ConnectCallback`, available from .NET 5 (and
  `SocketsHttpHandler` itself from .NET Core 2.1, with no .NET Framework equivalent). The callback
  hands you the connection to open rather than the address chosen, so resolve and check the addresses
  inside it and connect to the one you validated - it is the place to do this, not a check that
  happens on its own

## Taint Sinks

`HttpClient.GetAsync()`, `HttpClient.SendAsync()`, `WebClient.DownloadString()`, `WebRequest.Create()`

## Remediation Steps

- Create a URL validator that checks URLs against an allowlist of allowed domains/schemes
- Implement IP range checks covering both IPv4 and IPv6 private/reserved ranges
- Use `Dns.GetHostAddresses()` to resolve and validate IPs after initial URL validation
- Configure HttpClient with `AllowAutoRedirect = false` and `UseProxy = false`
- Block cloud metadata endpoints (169.254.169.254, metadata.google.internal) explicitly
- Return generic error messages to prevent information disclosure during validation failures
