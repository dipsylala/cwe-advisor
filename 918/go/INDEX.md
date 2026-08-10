# CWE-918: Server-Side Request Forgery (SSRF) - Go

## LLM Guidance

SSRF in Go applications happens when a user-supplied URL flows into `http.Get()`, `http.Client.Do()`, or a similar call without validation, letting attackers reach internal services or cloud metadata endpoints (`169.254.169.254`). Validation must happen at two points: parse the URL and check scheme/host against an allowlist before the request, and revalidate the resolved IP inside a custom `Transport.DialContext`, because `http.Client` performs its own DNS resolution that can differ from an earlier lookup (DNS rebinding). Never rely on hostname/IP checks alone without also disabling or revalidating redirects via `CheckRedirect`.

## Key Principles

- Validate the full URL (scheme, host) against an explicit allowlist of permitted domains before any request - reject anything not on the list
- Restrict scheme to `https://` only unless there is a specific need for `http://`
- Resolve the hostname and reject private/loopback/link-local/multicast IP ranges (`net.IP.IsPrivate()`, `IsLoopback()`, `IsLinkLocalUnicast()`, `IsLinkLocalMulticast()`), including IPv4-mapped IPv6 forms and metadata ranges (`169.254.0.0/16`)
- Revalidate the resolved IP inside a custom `http.Transport.DialContext`, not just before the request - the default dialer performs its own DNS lookup that can return a different address (DNS rebinding)
- Set `http.Client.CheckRedirect` to reject or revalidate each redirect target against the same allowlist/IP checks - the default client follows up to 10 redirects automatically
- Never pass unvalidated user input directly to `http.Get()`, `http.Client.Do()`, or `http.Client.Post()`

## Remediation Steps

- Locate - Find `http.Get()`, `http.Client.Do()`/`Get()`/`Post()` calls where the URL originates from request parameters, form values, JSON bodies, or webhook configuration
- Trace data flow - Follow the URL from its source (e.g. `r.URL.Query().Get("url")`) to the request call, noting any parsing (`net/url.Parse`) along the way
- Replace the unsafe pattern - Parse the URL and check that scheme is `https` and hostname is on an explicit allowlist before constructing the request
- Break taint after allowlist validation - Use the parsed, allowlist-confirmed `url.URL` value for the request, not the original raw string
- Harden configuration - Build the `http.Client` with a custom `Transport.DialContext` that re-resolves and re-validates the IP at connection time, plus a `CheckRedirect` that rejects or revalidates redirect targets
- Test - Attempt requests to `127.0.0.1`, `169.254.169.254`, RFC 1918 ranges, and a domain that redirects to an internal address; confirm all are blocked

## Safe Pattern

```go
import (
    "context"
    "fmt"
    "net"
    "net/http"
    "time"
)

var allowedHosts = map[string]bool{"api.example.com": true}

func isPrivateIP(ip net.IP) bool {
    return ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
        ip.IsLinkLocalMulticast() || ip.IsPrivate()
}

// SAFE: allowlist + IP validation, revalidated at dial time, redirects blocked
// Pass the allowlist-confirmed host to the dialer, not the raw request value.
func newSafeClient() *http.Client {
    dialer := &net.Dialer{Timeout: 5 * time.Second}
    return &http.Client{
        Timeout: 10 * time.Second,
        Transport: &http.Transport{
            DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
                host, port, err := net.SplitHostPort(addr)
                if err != nil {
                    return nil, err
                }
                if !allowedHosts[host] {
                    return nil, fmt.Errorf("host not allowed: %s", host)
                }
                ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
                if err != nil {
                    return nil, err
                }
                for _, ip := range ips {
                    if isPrivateIP(ip.IP) {
                        return nil, fmt.Errorf("private IP blocked: %s", ip.IP)
                    }
                }
                return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
            },
        },
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse // do not follow redirects
        },
    }
}
```
