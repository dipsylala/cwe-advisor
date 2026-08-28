# CWE-918: Server-Side Request Forgery (SSRF) - Java

## LLM Guidance

SSRF occurs when attackers manipulate server-side requests to access internal resources, cloud metadata endpoints, or bypass network controls.

The primary defence is to validate URLs against an allowlist of permitted domains/IPs, block private IP ranges (RFC 1918, loopback, link-local), and restrict protocols to `https://` only.

## Key Principles

- Validate all URLs against allowlists of permitted domains/IPs before making requests
- Block private, loopback, link-local, multicast, and cloud metadata address ranges using `InetAddress` checks
- Restrict protocols to HTTPS only to prevent file:// or jar:// exploits
- Implement DNS resolution checks to detect rebinding attacks
- Use network-level protections and egress filtering
- Put the range predicate in one place and call it from every validator and from the connection-time check, so they cannot disagree about what counts as internal
- Use JDK predicates only where they exist and byte tests where they do not: `isSiteLocalAddress()` sounds like private IPv6 and matches only the deprecated `fec0::/10`, so `fc00::/7` needs its own test, and there is no method at all for `0.0.0.0/8`, `100.64.0.0/10`, or `192.0.0.0/24`
- Block the whole of `169.254.0.0/16` rather than the single address `169.254.169.254` - that covers the Azure and Alibaba metadata endpoints and anything else on that interface
- Handle every IPv6 form carrying an IPv4 address: the JDK normalizes `::ffff:127.0.0.1` to an `Inet4Address`, but the compatible form `::7f00:1` is not normalized and every predicate returns false for it, and NAT64 (`64:ff9b::7f00:1`), 6to4 and Teredo addresses spell a v4 address inside an ordinary-looking v6 prefix - NAT64 is the one that routes in practice
- Fail closed when resolution raises, so a name that cannot be checked is not fetched, and disable redirect following so a permitted host cannot redirect out of the allowlist - checking which client is in use first, because the defaults already differ. `java.net.http.HttpClient` (JDK 11+) defaults to `Redirect.NEVER` and Reactor Netty behind `WebClient` defaults to not following, so neither needs the change; `HttpURLConnection`, reached through `URL.openConnection()`, `URL.openStream()` and `RestTemplate` on `SimpleClientHttpRequestFactory`, follows by default and is the one that does. Apache HttpClient offers `disableRedirectHandling()` on its builder

- A proxy silently voids the pinning: without disabling it the client uses the JVM's default proxy
  selector, which reads `http.proxyHost`/`https.proxyHost`, and a proxied request resolves the target
  at the proxy - so the address just validated is not the one reached
- `java.net.http.HttpClient` cannot be pinned at all: its builder exposes no DNS, socket or connection
  hook, so plan around Apache HttpClient 5's `DnsResolver` instead. And never return `null` from a
  custom resolver - that hands back an unresolved address which the socket layer then resolves itself,
  at connect time, with no validation

## Taint Sinks

`URL.openConnection()`, `URL.openStream()`, `HttpClient.send()`, `RestTemplate.getForObject()`, `HttpURLConnection.connect()`

## Remediation Steps

- Create an allowlist of permitted domains/hosts for outbound requests
- Parse and validate URLs before making requests, checking scheme and host
- Resolve all host A/AAAA records with `InetAddress.getAllByName()` and check if any resolved IP is in a blocked range
- Reject URLs targeting private IPs, localhost, cloud metadata endpoints (169.254.169.254)
- Configure HttpClient with strict redirect and timeout policies (disable redirects if possible)
- Log all outbound requests for monitoring and incident response
