# CWE-215: Insertion of Sensitive Information Into Debugging Code

## LLM Guidance

Insertion of sensitive information into debugging code occurs when debug statements, verbose logging, stack traces, or development features expose passwords, tokens, internal paths, SQL queries, or system architecture in production environments, enabling information disclosure and attack reconnaissance.

## Key Principles

- Never expose diagnostic or debugging instrumentation to untrusted clients
- Route by what the finding is about: debug functionality reachable at all is CWE-489, sensitive detail leaking through ordinary error handling is CWE-209, and sensitive data written to logs from any source is CWE-532; this entry is debug instrumentation that exposes sensitive information
- Runtime responses must be constructed independently of debug or developer-only state
- Separate development-time debugging from production error handling
- Implement environment-specific configurations that disable debug features in production, reading from config that defaults closed - a commented-out `DEBUG = True` still ships when a later edit or merge uncomments it
- Register debug routes only outside production so a production build has no handler to reach, rather than leaving a flag a config change or a mistaken deploy can flip back on; restricting by network location is not equivalent, since anything that pivots inside the network reaches it
- Allowlist which fields a debug endpoint or debug log emits: a blocklist leaks the next secret added to the config, and a logger that dumps a whole request object leaks the `Authorization` header, a session cookie, or a nested token the filter never anticipated
- Log sensitive operations securely without exposing credential values or internal paths

## Remediation Steps

- Identify debug mode flags, verbose logging, and debug endpoints in production code
- Locate error handlers that reveal stack traces or internal details to users
- Disable all debug modes and verbose error output in production environments
- Replace detailed error messages with generic user-facing responses
- Remove or conditionally disable debug logging that records passwords, tokens, or API keys
- Review exception handling to ensure stack traces and system details are logged server-side only - truncating the exception (`str(e)[:100]`) still surfaces the start of a SQL query or a path; replace the message rather than shortening it
