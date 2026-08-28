# CWE-918: Server-Side Request Forgery (SSRF) - PHP

## LLM Guidance

Server-Side Request Forgery (SSRF) allows attackers to make the server perform HTTP requests to arbitrary destinations, potentially accessing internal services, cloud metadata endpoints, or bypassing firewalls. Always validate URLs against an allowlist of permitted domains, block private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16), and restrict protocols to HTTPS only.

## Key Principles

- Use strict allowlist validation for permitted domains before making requests
- Block private, reserved, and loopback IP ranges using PHP's filter functions
- Disable URL redirects or validate redirect destinations
- Restrict protocols to HTTPS only, never allow file://, gopher://, or other schemes - check the scheme after `parse_url()` and constrain cURL itself, since the `parse_url()` test governs only your own branch and not what cURL will agree to fetch. `CURLOPT_PROTOCOLS` is deprecated from libcurl 7.85.0 and cannot express every protocol; prefer `CURLOPT_PROTOCOLS_STR` where PHP 7.3 and cURL 7.85 are available, and note that neither option enables a protocol by itself - it only restricts
- Implement DNS rebinding protection by validating all A/AAAA records before connecting and enforcing egress controls
- Pin the request to the validated IP with `CURLOPT_RESOLVE => ["host:port:ip"]` rather than passing the original URL to cURL for re-resolution - `parse_url()` and cURL's own URL parser can disagree on malformed input, so the host that was validated is not guaranteed to be the host cURL would otherwise connect to
- Read PHP's filter flags before writing checks by hand, because they cover more than is often
  assumed: `FILTER_FLAG_NO_RES_RANGE` already denies `0.0.0.0/8`, `169.254.0.0/16`, `127.0.0.0/8`,
  `240.0.0.0/4`, `::1/128`, `::/128`, `::FFFF:0:0/96` and `FE80::/10`, so the metadata address is
  inside it. What the flags genuinely miss is `100.64.0.0/10` (CGNAT), `192.0.0.0/24` and the NAT64
  prefix `64:ff9b::/96`, which spells an IPv4 address inside an ordinary IPv6 one - add those
- On PHP 8.2 and later prefer `FILTER_FLAG_GLOBAL_RANGE`, which allows only global addresses and so
  fails closed on ranges added later, rather than enumerating what to deny
- `CURLOPT_FOLLOWLOCATION` already defaults to disabled, so treat an explicit `false` as documenting
  intent and look instead for the code that switched it on; where redirects are genuinely needed,
  re-run the full address check on every hop and constrain `CURLOPT_REDIR_PROTOCOLS`, since libcurl
  otherwise allows HTTP, HTTPS, FTP and FTPS on a redirect
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
- Set timeouts and restrict allowed protocols with `CURLOPT_PROTOCOLS => CURLPROTO_HTTPS`
- Pin the connection to the validated IP with `CURLOPT_RESOLVE` so cURL cannot independently re-resolve or re-parse the host
