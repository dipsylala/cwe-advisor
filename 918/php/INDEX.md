# CWE-918: Server-Side Request Forgery (SSRF) - PHP

## LLM Guidance

Server-Side Request Forgery (SSRF) allows attackers to make the server perform HTTP requests to arbitrary destinations, potentially accessing internal services, cloud metadata endpoints, or bypassing firewalls. Always validate URLs against an allowlist of permitted domains, block private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16), and restrict protocols to HTTPS only.

## Key Principles

- Use strict allowlist validation for permitted domains before making requests
- Block private, reserved, and loopback IP ranges using PHP's filter functions
- Disable URL redirects or validate redirect destinations
- Restrict protocols to HTTPS only, never allow file://, gopher://, or other schemes
- Implement DNS rebinding protection by validating all A/AAAA records before connecting and enforcing egress controls
- Pin the request to the validated IP with `CURLOPT_RESOLVE => ["host:port:ip"]` rather than passing the original URL to cURL for re-resolution - `parse_url()` and cURL's own URL parser can disagree on malformed input, so the host that was validated is not guaranteed to be the host cURL would otherwise connect to
- Block the whole `169.254.0.0/16` range rather than the single address `169.254.169.254`, and include the ranges PHP's own filter flags miss - `100.64.0.0/10` (CGNAT), `192.0.0.0/24`, `0.0.0.0/8` and the NAT64 prefix `64:ff9b::/96`, which spells an IPv4 address inside an ordinary IPv6 one
- Set `CURLOPT_FOLLOWLOCATION = false`, or re-run the full address check on every hop, since a permitted host can redirect out of the allowlist after validation
- Clear `CURLOPT_PROXY` for the request: an environment proxy forwards the hostname to be resolved at the other end, which makes the address you validated irrelevant
- Confirm what was actually reached with `CURLINFO_PRIMARY_IP` after the transfer, as a check that the connection went where the validation said it would

## Taint Sinks

`curl_exec()`, `file_get_contents()`, `fopen()`, `fsockopen()`, `SoapClient()`

## Remediation Steps

- Extract and validate the hostname from user-supplied URLs
- Use `filter_var()` with `FILTER_VALIDATE_IP` and flags `FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE` to block dangerous IPs
- Check hostname against an allowlist of permitted domains
- Ensure only HTTPS protocol is used via `parse_url()`
- Disable `CURLOPT_FOLLOWLOCATION` or validate all redirect targets
- Set timeouts and use `CURLOPT_PROTOCOLS` to restrict allowed protocols
- Pin the connection to the validated IP with `CURLOPT_RESOLVE` so cURL cannot independently re-resolve or re-parse the host
