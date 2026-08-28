# CWE-223: Omission of Security-relevant Information

## LLM Guidance

Omission of security-relevant information occurs when applications fail to log critical security events such as login failures, access denials, privilege escalations, and data modifications. This prevents effective security monitoring, incident response, compliance auditing, and attack detection. The core fix is implementing comprehensive logging of all security-relevant events while ensuring logged information doesn't expose sensitive data. Most findings reported here are really CWE-778 (Insufficient Logging), the narrower case of a missing or incomplete log entry - check that first. This entry also covers security-relevant *output* generally: a warning, prompt, scanner report, or downstream API response that says something is wrong without saying what, leaving the reader unable to judge the actual risk.

## Key Principles

- Ensure exceptions and failure modes do not disclose sensitive data or bypass security checks; fail closed
- Log all authentication and authorization events including both successes and failures
- Implement structured logging with sufficient context for security analysis and forensics - the specific reason, not just a severity or a pass/fail rollup
- Where the recipient may be the attacker, the detail belongs somewhere else rather than nowhere: authentication and account-lookup responses must stay identical across causes (CWE-209), so route the specific reason to the server-side log, an admin view, or the authenticated user's own security page
- Check the display layer too: preserving a `details` array in the backend while the template renders only the top-level status relocates the omission rather than fixing it, as does logging the reason at a level nobody reads
- Comply with regulatory audit requirements (PCI-DSS, HIPAA, SOX, GDPR)

## Remediation Steps

- Find unlogged security events - Identify missing logs for authentication attempts (login/logout), authorization failures, privilege changes, sensitive data access, and configuration modifications
- Check authentication flows - Ensure logging covers login, logout, password reset, MFA, and session lifecycle events
- Review authorization points - Log all access denied events, role/permission checks, and resource access attempts
- Identify sensitive operations - Track data modifications (create, update, delete), administrative actions, and configuration changes
- Trace audit requirements - Map logging to compliance obligations and regulatory standards
