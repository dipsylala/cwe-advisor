# CWE-942: Permissive Cross-domain Policy with Untrusted Domains - JavaScript

## LLM Guidance

In Node.js/Express APIs, this weakness usually appears as the `cors` npm package configured with a wildcard origin, a call to `app.use(cors())` with no arguments (whose default `origin` is `*`), or hand-written middleware that copies `req.headers.origin` straight into `Access-Control-Allow-Origin`. Express has no built-in CORS handling, so a permissive configuration is easy to introduce and easy to miss in review. The primary remediation is an explicit origin allowlist, checked with an exact or pattern match, never a wildcard or an unconditional reflection - and never combined with `Access-Control-Allow-Credentials: true`.

## Key Principles

- Configure the `cors` package with an `origin` allowlist function rather than a literal `*` or `origin: true` (which reflects the request's `Origin` header, the same as a wildcard)
- Never set `Access-Control-Allow-Credentials: true` alongside `Access-Control-Allow-Origin: *`; only pair credentials with a specific, validated origin
- Restrict `methods` and `allowedHeaders` in the `cors` config to what each route actually needs
- If matching subdomains with a RegExp, anchor the pattern with an escaped literal dot (`/\.example\.com$/`), not an unanchored suffix match that also matches `evilexample.com`
- Send `Vary: Origin` when setting `Access-Control-Allow-Origin` dynamically, so shared caches do not serve one origin's response to another
- Audit every route for a leftover default `app.use(cors())` alongside a route-specific, correctly configured instance - the default still applies to any route the newer configuration does not cover
- The preflight `OPTIONS` response is not an authorization decision: a simple request never triggers one, so an endpoint reachable without a preflight has no CORS-based protection at all

## Taint Sinks

`cors({ origin: '*' })`, `cors({ origin: true })`, `res.setHeader('Access-Control-Allow-Origin', req.headers.origin)`

## Remediation Steps

- Locate - Search for `Access-Control-Allow-Origin`, `cors(`, and any custom CORS middleware
- Trace data flow - Confirm whether the origin value is a literal `*`, `origin: true`, a reflected `req.headers.origin`, or a real allowlist check
- Replace the unsafe pattern - Replace the wildcard or reflection with an `origin(origin, callback)` function (via the `cors` package, preferred) that checks the incoming origin against a fixed list and signals the result as `callback(null, true)` or `callback(new Error(...))`
- Bind, encode, validate, or authorize - Use exact string comparison or a properly anchored allowlist pattern; decide explicitly whether requests with no `Origin` header (server-to-server, curl) are allowed
- Break taint after allowlist validation - Pass only the matched allowlist entry to `Access-Control-Allow-Origin`, not the raw `req.headers.origin` value
- Harden configuration - Enable `credentials: true` only alongside the allowlist, and scope `methods`/`allowedHeaders` per route
- Test - Send requests from an allowed origin, an untrusted origin, and a credentialed request; confirm the untrusted origin receives no matching `Access-Control-Allow-Origin` header and that `Access-Control-Allow-Credentials` never appears with `*`
