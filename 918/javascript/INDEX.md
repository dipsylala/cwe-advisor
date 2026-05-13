# CWE-918: Server-Side Request Forgery (SSRF) - JavaScript/Node.js

## LLM Guidance

SSRF in Node.js occurs when applications fetch remote resources using user-supplied URLs without validation, enabling attackers to access internal services, cloud metadata endpoints, and bypass firewalls.

**Primary Defence:** Validate URLs against an allowlist of permitted domains, resolve all A/AAAA records before connecting, block private/reserved address ranges, disable redirects, and enforce network egress controls.

## Key Principles

- Allowlist domains: Only permit requests to explicitly approved domains/hosts
- Block private networks: Reject private, loopback, link-local, metadata, and reserved IPv4/IPv6 ranges
- Disable redirects: Prevent attackers from bypassing validation via HTTP redirects
- Parse and validate: Use `URL` constructor to parse and validate scheme, hostname, and port

## Remediation Steps

- Create an allowlist of permitted domains/hosts for external requests
- Parse user input with `new URL()` and validate hostname against allowlist
- Reject private IP addresses and localhost addresses
- Disable automatic redirect following in HTTP clients
- Validate resolved IPs before connecting (DNS rebinding protection)
- Use network-level controls to restrict outbound connections

## Safe Pattern

```javascript
const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');

const ALLOWED_HOSTS = ['api.trusted-service.com', 'cdn.example.com'];

function isGlobalAddress(address) {
  const parsed = ipaddr.parse(address);
  const normalized = parsed.kind() === 'ipv6' && parsed.isIPv4MappedAddress()
    ? parsed.toIPv4Address()
    : parsed;
  return normalized.range() === 'unicast';
}

async function safeFetch(userUrl) {
  const url = new URL(userUrl); // Throws on invalid URL
  
  if (!ALLOWED_HOSTS.includes(url.hostname)) {
    throw new Error('Domain not allowed');
  }
  
  if (url.protocol !== 'https:') {
    throw new Error('Only HTTPS allowed');
  }

  const records = await dns.lookup(url.hostname, { all: true });
  if (records.length === 0 || records.some((record) => !isGlobalAddress(record.address))) {
    throw new Error('Blocked address range');
  }
  
  // Pair DNS validation with egress firewall rules to prevent second-resolution bypasses.
  return fetch(url.href, { redirect: 'manual' });
}
```
