# CWE-501: Trust Boundary Violation

## LLM Guidance

Trust boundary violations occur when untrusted data (user input, HTTP requests) is mixed into the same data structure as trusted data - most commonly stored in a trusted context like a session object or internal object - without validation, so the two can no longer be reliably distinguished downstream. This enables session poisoning, privilege escalation, and security control bypass, since code that trusts the structure as a whole ends up trusting the untrusted portion too. Core fix: explicitly validate untrusted data before it is mixed into or stored in a trusted context, and keep trusted and untrusted data in clearly separate structures wherever possible.

## Key Principles

- Treat trust boundaries explicitly - never allow data to cross without validation and authorization
- Apply least privilege when storing data in trusted contexts
- Never assume session, cache, or internal object data is inherently safe
- Validate and sanitize before storing untrusted data in trusted contexts
- Separate trusted and untrusted data storage mechanisms

## Remediation Steps

- Examine data_paths to identify where untrusted data crosses into trusted contexts
- Locate trust boundaries - session storage, caches, internal objects, security contexts
- Add validation before storing untrusted data in sessions, caches, or internal objects
- Check for missing validation and trust assumptions in existing code
- Assess impact - determine if attackers can control session variables, roles, or security decisions
- Implement authorization checks when reading data from trusted contexts
