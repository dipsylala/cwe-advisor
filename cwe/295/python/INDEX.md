# CWE-295: Improper Certificate Validation - Python

## LLM Guidance

Improper certificate validation occurs when Python applications disable SSL/TLS certificate verification (e.g., `requests.get(url, verify=False)` or `urllib3` with `cert_reqs='CERT_NONE'`), enabling man-in-the-middle attacks where attackers intercept and modify encrypted traffic. The core fix is to enable certificate validation by using default settings or explicitly setting `verify=True`, allowing Python to validate certificates against trusted certificate authorities.

## Key Principles

- Always enable certificate validation - Never disable SSL/TLS verification in production code
- Use system certificate stores - Rely on Python's default CA bundle or OS-provided certificates
- Handle certificate errors properly - Log and investigate certificate failures rather than disabling validation
- Keep dependencies updated - Ensure `requests`, `urllib3`, and `certifi` libraries are current
- Use certificate pinning for critical connections - Pin specific certificates for high-security requirements
- `ssl.create_default_context()` is the correct starting point - it sets `check_hostname=True` and `verify_mode=CERT_REQUIRED` - while a bare `ssl.SSLContext(...)` starts with verification off, so constructing one directly is the quiet form of this weakness
- Pass `server_hostname=` to `SSLContext.wrap_socket()`: without it the chain is verified and the name is not, which authenticates nobody, and nothing in the code reads as disabled
- `urllib.request.urlopen()` uses the default context and verifies; the finding is usually an explicitly constructed unverified context handed to it
- `REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE` replace the trust store from the environment, so a CA added there is a deployment-time change nothing in the code shows - check the environment as well as the source

## Taint Sinks

`requests.get(..., verify=False)`, `urllib3` `cert_reqs='CERT_NONE'`

## Remediation Steps

- Remove all instances of `verify=False` from `requests` calls
- Remove `cert_reqs='CERT_NONE'` from `urllib3` configurations
- Use `verify=True` explicitly or rely on secure defaults
- Specify custom CA bundles with `verify='/path/to/ca-bundle.crt'` only when necessary
- Update certificate-related packages - `pip install --upgrade requests urllib3 certifi`
- Test connections to ensure certificate validation works in all environments
