# CWE-295: Improper Certificate Validation - JavaScript

## LLM Guidance

Improper certificate validation in Node.js applications allows man-in-the-middle attacks where attackers intercept and modify HTTPS communications. `rejectUnauthorized` defaults to `true` in `tls.connect()`, `https.request()`, and every HTTP client built on them, so the finding is almost always an explicit `rejectUnauthorized: false` (frequently reached through an `https.Agent`/`http.Agent` passed to axios, node-fetch, or undici, not just the raw `https` module) or the process-wide `NODE_TLS_REJECT_UNAUTHORIZED=0` environment variable. The fix is to remove the override and let the default validation run, adding a custom CA only when one is genuinely needed.

## Key Principles

- `rejectUnauthorized: false` disables both chain and hostname validation for that connection; there is no partial form
- `NODE_TLS_REJECT_UNAUTHORIZED=0` disables it process-wide for every TLS connection the process makes, not just one client - treat it as equivalent to finding the option hardcoded in every HTTP call in the codebase
- undici's `setGlobalDispatcher(new Agent({ connect: { rejectUnauthorized: false } }))` has the same process-wide blast radius as the environment variable, but for undici and the global `fetch()` it backs in modern Node - check for it even when no `https.Agent` bypass is present
- For a private/internal CA, pass it via the `ca` option (`tls.connect`, `https.request`, or the client library's equivalent) rather than disabling validation
- A custom `checkServerIdentity` callback must return `undefined` to accept the connection and an `Error` to reject it - it does not throw on rejection, and returning anything else (including `false`) is not a documented way to fail the check
- HSTS (`Strict-Transport-Security`) governs whether a *browser* upgrades future requests to HTTPS - it has no effect on whether this application's own HTTP client validates the certificates it receives, so it does not belong in this fix

## Taint Sinks

`rejectUnauthorized: false` (directly, or via an `https.Agent`/`http.Agent` passed to `axios`, `node-fetch`, or a client library's `agent` option), `NODE_TLS_REJECT_UNAUTHORIZED='0'`, `setGlobalDispatcher()` with an `Agent` carrying `connect: { rejectUnauthorized: false }`

## Remediation Steps

- Locate - search for `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED`, and any `https.Agent`/`Agent` construction passed as a client's `agent`/`httpsAgent` option
- Trace data flow - confirm which HTTP client (raw `https`, axios, node-fetch, undici/global `fetch`) consumes the affected agent or dispatcher
- Replace the unsafe pattern - remove the `rejectUnauthorized: false` override and the environment variable; for undici, remove the insecure `Agent` from `setGlobalDispatcher()`
- Configure trusted CAs - pass the internal CA via the `ca` option instead of disabling validation
- If pinning is required, implement `checkServerIdentity` to check the expected certificate/public key and return `undefined` on success, an `Error` otherwise
- Test - connect to endpoints presenting expired, self-signed, and wrong-hostname certificates and confirm the client rejects them with a certificate error
