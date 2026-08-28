# CWE-918: Server-Side Request Forgery (SSRF) - Go

## LLM Guidance

SSRF in Go applications happens when a user-supplied URL flows into `http.Get()`, `http.Client.Do()`, or a similar call without validation, letting attackers reach internal services or cloud metadata endpoints (`169.254.169.254`). Validation must happen at two points: parse the URL and check scheme/host against an allowlist before the request, and revalidate the resolved IP inside a custom `Transport.DialContext`, because `http.Client` performs its own DNS resolution that can differ from an earlier lookup (DNS rebinding). Never rely on hostname/IP checks alone without also disabling or revalidating redirects via `CheckRedirect`.

## Key Principles

- Validate the full URL (scheme, host) against an explicit allowlist of permitted domains before any request - reject anything not on the list
- Restrict scheme to `https://` only unless there is a specific need for `http://`
- Resolve the hostname and reject private, loopback, link-local and multicast addresses, but do not
  build the check on `IsPrivate` alone. Go documents it as covering only `10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16` and `fc00::/7`, and states outright that it "does not describe a
  security property of addresses, and should not be used for access control". It returns false for
  `169.254.169.254`, which is the address this finding usually exists to protect - that one is caught
  by `IsLoopback()`, `IsLinkLocalUnicast()` and `IsLinkLocalMulticast()` alongside it, plus an explicit
  CIDR test for the ranges no standard-library predicate covers (`100.64.0.0/10`, `192.0.0.0/24`,
  `0.0.0.0/8`, and NAT64 `64:ff9b::/96`)
- `net.IP.IsPrivate` arrived in Go 1.17 and the `net/netip` package in Go 1.18, so on an older
  toolchain these predicates have to be written by hand
- Revalidate the resolved IP inside a custom `http.Transport.DialContext`, not just before the request - the default dialer performs its own DNS lookup that can return a different address (DNS rebinding); split the `addr` argument with `net.SplitHostPort()` and dial `net.JoinHostPort(validatedIP, port)` rather than the hostname, so no second resolution happens
- Set `http.Client.CheckRedirect` to reject or revalidate each redirect target against the same
  allowlist and IP checks - with `CheckRedirect` nil the client stops after 10 consecutive *requests*,
  which is a loop guard rather than a limit on where it will go. Note the callback receives the
  upcoming `*Request` and the ones already made, so it sees URLs and not resolved addresses; the IP
  check still has to happen at dial time
- Never pass unvalidated user input directly to `http.Get()`, `http.Client.Do()`, or `http.Client.Post()`

## Taint Sinks

`http.Get()`, `http.Client.Do()`, `http.Client.Post()`, `http.Client.Head()`

## Remediation Steps

- Locate - Find `http.Get()`, `http.Client.Do()`/`Get()`/`Post()` calls where the URL originates from request parameters, form values, JSON bodies, or webhook configuration
- Trace data flow - Follow the URL from its source (e.g. `r.URL.Query().Get("url")`) to the request call, noting any parsing (`net/url.Parse`) along the way
- Replace the unsafe pattern - Parse the URL and check that scheme is `https` and hostname is on an explicit allowlist before constructing the request
- Break taint after allowlist validation - Use the parsed, allowlist-confirmed `url.URL` value for the request, not the original raw string
- Harden configuration - Build the `http.Client` with a custom `Transport.DialContext` that re-resolves and re-validates the IP at connection time, plus a `CheckRedirect` that rejects or revalidates redirect targets
- Test - Attempt requests to `127.0.0.1`, `169.254.169.254`, RFC 1918 ranges, and a domain that redirects to an internal address; confirm all are blocked
