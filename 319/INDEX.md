# CWE-319: Cleartext Transmission of Sensitive Information

## LLM Guidance

Cleartext transmission occurs when sensitive data (passwords, tokens, PII, API keys, payment data) is sent over networks without encryption, making it readable to attackers. Network sniffing, man-in-the-middle attacks, and compromised infrastructure allow easy interception of unencrypted HTTP, WebSocket (ws://), FTP, or plaintext database traffic. The core fix: always use TLS/HTTPS and encrypted transport for all sensitive data.

## Key Principles

- Never transmit sensitive data over cleartext channels (HTTP, ws://, FTP, unencrypted databases)
- Require TLS 1.2+ for all communications, preferably TLS 1.3
- Use HTTPS for entire site, not just login/sensitive pages
- Implement certificate validation to prevent MITM attacks
- Apply encryption at transport layer and application layer when needed
- Moving a URL from `http://` to `https://` does not close the finding while either half of client validation is off: chain validation and hostname verification are separate settings, and a client that checks the chain but skips the name authenticates nobody - the attacker needs one valid certificate for a domain they own, which is free
- Treat the HTTP-to-HTTPS redirect as damage limitation rather than the fix: the plaintext request has already gone out by the time the 301 arrives, carrying any cookie without the `Secure` flag, and a non-browser client that POSTs to `http://` has sent the whole body first
- HSTS stops the *next* browser request and nothing else - API clients, mobile SDKs, `curl` and service-to-service callers ignore the header, so for those the scheme is fixed in code or configuration
- Database connection modes have the same two-part split: PostgreSQL `require` encrypts and verifies nothing and `verify-ca` checks the chain but not the host name, so only `verify-full` does both - as with MySQL's `REQUIRED`, `VERIFY_CA` and `VERIFY_IDENTITY`

## Remediation Steps

- Review flaw details to identify file, line number, and what sensitive data is transmitted in cleartext
- Trace data flow to determine protocol (HTTP vs HTTPS, ws:// vs wss://, FTP vs SFTP)
- Migrate all endpoints to HTTPS/TLS - update URLs from http:// to https:// and ws:// to wss://
- Configure TLS 1.2 minimum (disable TLS 1.0/1.1, SSL), prefer TLS 1.3
- Enable HSTS (HTTP Strict Transport Security) headers to enforce HTTPS
- Validate server certificates properly-don't disable certificate checks in production
