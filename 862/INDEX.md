# CWE-862: Missing Authorization

## LLM Guidance

Missing Authorization occurs when a code path performs a sensitive action or returns sensitive data without any check on whether the authenticated caller is permitted to do so - the check is absent, not wrong. The usual cause is an endpoint that verifies the caller is logged in but never checks role, permission, or resource ownership, an admin-only function reachable by any authenticated user, or a new route never wired into the shared authorization middleware or decorator used by comparable routes. This differs from CWE-306 (Missing Authentication, no identity check at all) and CWE-863 (Incorrect Authorization, a check exists but its logic is flawed) - CWE-862 always involves a caller whose identity is known but whose permission was never evaluated. Remediate by adding an explicit authorization check - role, permission, or ownership - on every sensitive path, applied through the same centralized mechanism used elsewhere.

## Key Principles

- Authentication (who is the caller) and authorization (what is the caller allowed to do) are separate steps; confirming identity is not sufficient to permit an action
- Every sensitive action - state change, non-public data read, admin capability - must have an explicit authorization check on the server before it executes
- Enforce authorization by default through centralized middleware, decorators, filters, or a policy layer, so new routes inherit the same requirement instead of needing it added by hand
- Check both the action (does the caller hold the required role or permission) and the resource (does the caller own or have a granted relationship to this specific record)
- Do not rely on hiding UI controls, client-side route guards, or trusting a role/permission value supplied by the client
- Fail closed - if the authorization decision cannot be evaluated, deny the request rather than default to allow
- "Authenticated" is not "authorized": a positively named `requireAuthentication` gate makes the route read as protected, and the distance between logged in and allowed is exactly what an attacker covers by changing an identifier in the URL
- Attach the permission and ownership checks through the same centralized mechanism every comparable route uses, so a new or overlooked route inherits them instead of depending on someone remembering
- Check ownership against a server-loaded copy of the resource, never a client-supplied flag - an authenticated caller with the right role still must not reach a record that is not theirs
- Where the request carries an object identifier, CWE-639 usually gives the more concrete remediation; no identity check at all is CWE-306, and a check that runs with wrong logic is CWE-863

## Remediation Steps

- Locate - Enumerate routes, RPC methods, background jobs, and resolvers that perform sensitive actions or return sensitive data
- Diff against coverage - Compare that list against what the authorization middleware, decorator, or policy layer actually covers; treat anything not covered as a candidate gap
- Confirm the check is absent, not wrong - Verify no role, permission, or ownership check runs on the path at all; if a check exists but uses flawed logic, this is CWE-863, not CWE-862
- Determine the required permission - Identify what role, permission, or ownership relationship should gate the action, based on comparable protected paths
- Apply the fix - Add the missing check through the same centralized mechanism used by sibling routes, rather than an inline one-off check
- Cover resource-level access - For actions on a specific record, verify the caller owns or has a granted relationship to it, not just that they hold the right role
- Fail closed - Ensure the check denies access by default when the permission cannot be determined or the check errors
- Test directly against the endpoint - Call the route as an authenticated-but-unprivileged user and confirm the response is a 403, not a 200 or a UI-only restriction
