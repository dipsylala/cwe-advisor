# CWE-668: Exposure of Resource to Wrong Sphere

## LLM Guidance

Exposing resources (files, database connections, memory) to the wrong sphere of control occurs when internal resources become accessible outside intended boundaries (process, user, security context). This enables unauthorized access, resource exhaustion, and data leakage. Core principle: Resource visibility and accessibility must be explicitly defined and enforced by design, not inferred from request context.

## Key Principles

- Use local variables, context managers, and request-scoped objects instead of global or static resources
- Close file descriptors after fork() so child processes do not inherit sensitive resources from the parent
- Use thread-local storage, connection-per-request patterns, and per-user resource allocation to isolate by security context
- Close or clear resources explicitly when crossing security boundaries: connection pool returns, thread completion, process transitions
- Treat this as a router and take the fix from the child: information exposure is CWE-200, a handle inherited across `fork`/`exec` is CWE-402, a temporary file is CWE-377, a search path element is CWE-427, credentials are CWE-522, client-controlled critical state is CWE-642, permission bits are CWE-732, a cloneable secret-holding class is CWE-498, and a format string is CWE-134
- Per-request state held in a singleton, a servlet member field, or a module-level variable and then read by a concurrent request belonging to someone else is CWE-488 - the child most often filed here by mistake

## Remediation Steps

- Identify exposed resources - Find global variables, static instances, inherited file descriptors, and shared connections
- Determine wrong sphere - Check for cross-user access, process inheritance, thread leakage, and security context violations
- Properly scope resources - Replace global resources with context managers (`with` statements), local variables, or request-scoped objects
- Isolate by security context - Implement thread-local storage, connection-per-request, and close file descriptors before executing untrusted code
- Test cross-boundary access - Verify User A cannot access User B's resources and child processes don't inherit sensitive handles
- Add resource cleanup - Ensure proper closure/clearing at security boundaries (request end, thread completion, process fork)
