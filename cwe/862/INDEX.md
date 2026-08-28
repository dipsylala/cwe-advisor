# CWE-862: Missing Authorization

## LLM Guidance

Missing Authorization occurs when a code path performs a sensitive action or returns sensitive data without any check on whether the authenticated caller is permitted to do so - the check is absent, not wrong. The usual cause is an endpoint that verifies the caller is logged in but never checks role, permission, or resource ownership, or a new route never wired into the shared authorization middleware used by comparable routes. Remediate by adding an explicit check - role, permission, or ownership - on every sensitive path, through the same centralized mechanism used elsewhere.

## Key Principles

- Authentication (who is the caller) and authorization (what the caller may do) are separate steps: a positively named `requireAuthentication` gate makes a route read as protected, and the distance between logged in and allowed is exactly what an attacker covers by changing an identifier in the URL
- Every sensitive action - state change, non-public data read, admin capability - must have an explicit authorization check on the server before it executes
- Enforce authorization by default through centralized middleware, decorators, filters, or a policy layer, so new routes inherit the same requirement instead of needing it added by hand
- Check both the action (does the caller hold the required role or permission) and the resource (does the caller own or have a granted relationship to this specific record)
- Do not rely on hiding UI controls, client-side route guards, or trusting a role/permission value supplied by the client
- Fail closed - if the authorization decision cannot be evaluated, deny the request rather than default to allow
- Check ownership against a server-loaded copy of the resource, never a client-supplied flag - an authenticated caller with the right role still must not reach a record that is not theirs
- Let the response code follow what the caller is entitled to know exists. A role or permission gate on an endpoint that is not itself a secret answers 403. An object-level ownership check on a guessable identifier should instead scope the lookup itself - `WHERE id = ? AND owner_id = ?` - and answer 404 identically, in status and body, for "not yours" and "does not exist"; a 403 there confirms the record exists and turns the identifier space into an enumeration oracle
- Where the request carries an object identifier, CWE-639 usually gives the more concrete remediation; no identity check at all is CWE-306, and a check that runs with wrong logic is CWE-863

## Remediation Steps

- Locate - Enumerate routes, RPC methods, background jobs, and resolvers that perform sensitive actions or return sensitive data
- Diff against coverage - Compare that list against what the authorization middleware, decorator, or policy layer actually covers; treat anything not covered as a candidate gap
- Confirm the check is absent, not wrong - if a check runs but its logic is flawed, this is CWE-863
- Determine the required permission - Identify what role, permission, or ownership relationship should gate the action, based on comparable protected paths
- Apply the fix - Add the missing check through the same centralized mechanism used by sibling routes, rather than an inline one-off check
- Cover resource-level access - For actions on a specific record, verify the caller owns or has a granted relationship to it, not just that they hold the right role, and cover every operation on that resource - read, list, update, delete, export - rather than only the one the finding named
- Test directly against the endpoint - Call the route as an authenticated-but-unprivileged user and confirm the response is a denial rather than a 200 or a UI-only restriction: 403 where a role or permission is the gate, 404 where ownership of a guessable identifier is, since the scoped lookup is what the fix there looks like
