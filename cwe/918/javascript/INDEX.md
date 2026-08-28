# CWE-918: Server-Side Request Forgery (SSRF) - JavaScript

## LLM Guidance

SSRF in Node.js occurs when applications fetch remote resources using user-supplied URLs without validation, enabling attackers to access internal services, cloud metadata endpoints, and bypass firewalls.

**Primary Defence:** Validate URLs against an allowlist of permitted domains, resolve all A/AAAA records before connecting, block private/reserved address ranges, disable redirects, and enforce network egress controls.

## Key Principles

- Allowlist domains: Only permit requests to explicitly approved domains/hosts
- Block private networks: reject private, loopback, link-local, metadata and reserved IPv4/IPv6
  ranges, naming the CIDRs rather than the categories - `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `100.64.0.0/10`, `::1/128`, `fc00::/7` and
  `fe80::/10`. The IPv6 metadata address is a unique-local address (`fd00:ec2::254`), not a
  link-local one, so a filter written as "link-local plus metadata" misses it unless `fc00::/7` is
  in the list
- Disable redirects: Prevent attackers from bypassing validation via HTTP redirects
- Parse and validate: Use `URL` constructor to parse and validate scheme, hostname, and port
- Handle every IPv6 spelling of an IPv4 address, not just the mapped form: `::ffff:127.0.0.1`, the compatible form `::7f00:1`, and the NAT64 prefix (`64:ff9b::7f00:1`) all reach loopback while looking like ordinary IPv6 to a string check
- Resolve the hostname with `dns.promises.lookup(host, { all: true })` and check every returned address before connecting - with `ipaddr.js`, unmap via `toIPv4Address()` and require `ip.range() === 'unicast'` - then pin the connection to the address that was checked - Node's agent resolves again at connect time, which is the rebinding race

## Taint Sinks

`fetch()`, `axios.get()`, `http.request()`, `https.request()`, `XMLHttpRequest.open()`

## Remediation Steps

- Create an allowlist of permitted domains/hosts for external requests
- Parse user input with `new URL()` and validate hostname against allowlist
- Reject private IP addresses and localhost addresses
- Disable automatic redirect following, per client, since the defaults differ and none of them is
  safe by accident: `fetch` defaults to `redirect: 'follow'` and takes `'manual'` or `'error'`, and on
  the server `'manual'` returns the real 3xx with its `Location`, so following it by hand reopens the
  hole; `axios` defaults `maxRedirects` to 21 and needs `maxRedirects: 0`; Node's own `http.request()`
  does not follow redirects at all, so nothing is needed there. Global `fetch` also has a floor - it
  is unavailable or flag-gated before Node 18
- Validate resolved IPs before connecting (DNS rebinding protection)
- Use network-level controls to restrict outbound connections
