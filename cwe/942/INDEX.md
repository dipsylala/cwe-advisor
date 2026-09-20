# CWE-942: Permissive Cross-domain Security Policy with Untrusted Domains

## LLM Guidance

The permissive policy is the finding rather than a missing token: an over-broad `Access-Control-Allow-Origin`, a `crossdomain.xml`, or a `postMessage` handler that accepts any sender. The general origin-validation failure is CWE-346, and forged state-changing requests riding a victim's session are CWE-352.

## Key Principles

- Only allow specific trusted origins; never use `*` in production or reflect Origin headers dynamically
- Permit only required HTTP methods and headers to minimize the attack surface
- Omit `Access-Control-Allow-Credentials` unless absolutely necessary; browsers only honor `true`, and it must never be combined with wildcard origins
- Log CORS requests, track unexpected origins, and regularly review policy effectiveness

## Remediation Steps

- Check response headers for `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true` combinations
- Review CORS middleware for origin reflection patterns that echo back request origins without validation
- Replace wildcards with explicit allowlists of trusted domains in configuration
- Validate origin allowlists against business requirements; remove unused or overly broad entries
- Audit preflight handling to ensure OPTIONS responses don't permit excessive methods or headers
- Test CORS policies by sending requests from untrusted origins and verifying they're rejected
