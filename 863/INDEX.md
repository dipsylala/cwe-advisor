# CWE-863: Incorrect Authorization

## LLM Guidance

Incorrect Authorization occurs when an authorization check exists but its logic is flawed, letting an attacker satisfy a condition the developer did not intend. Common causes are denylist role checks that fail open on unexpected values, checks that validate resource type but not resource ownership, inverted or short-circuited boolean logic, and checks applied on some code paths but not others (an alternate HTTP method, a bulk endpoint, or a client-only check the server never repeats). This differs from CWE-862 (Missing Authorization), where no check exists at all - here the fix is to correct the logic, not add a missing check. It also overlaps with but is broader than CWE-639/IDOR: CWE-639 is specifically a user-controlled object identifier selecting another user's data, while CWE-863 covers the wider class of flawed authorization logic, including role and permission checks, control-flow gaps, and boolean errors.

## Key Principles

- Prefer allowlists (explicit permitted roles or permissions) over denylists - a denylist fails open when a new or unexpected value appears
- Re-run authorization server-side on every path that reaches the sensitive action, not only the primary UI path - cover alternate HTTP methods, API variants, and bulk/batch operations
- Never trust a client-supplied role, permission, or ownership claim; always resolve the acting user's authorization from a trusted server-side source
- Pair resource-type checks with resource-ownership or tenant checks - confirming "this is a document" is not the same as confirming "this is the caller's document"
- Scrutinize boolean logic for inversions, wrong operator precedence, and short-circuit mistakes (`||` where `&&` was intended)
- Fail closed - unmatched, unknown, or error states in the authorization decision must deny access, not default to allow

## Remediation Steps

- Locate - Find the authorization check guarding the sensitive action or resource, and confirm a check does exist (if none exists, this is CWE-862, not CWE-863)
- Trace the decision logic - Identify the exact condition, comparison, or lookup being evaluated and every code path that reaches the protected action
- Identify the flaw - Determine whether it is a denylist that should be an allowlist, an inverted or short-circuited boolean, a check missing ownership/tenant validation, an inconsistent check across duplicated code paths, or a check enforced only client-side
- Replace with correct logic - Rewrite as an explicit allowlist or permission lookup evaluated server-side, adding ownership or tenant validation alongside any resource-type check
- Ensure full path coverage - Apply the corrected check to every entry point that reaches the action, including all HTTP methods, API and UI routes, and batch operations
- Fail closed - Confirm unmatched, unknown, or error conditions in the check result in denial by default
- Test - Verify with role-boundary tests (new/unexpected roles, adjacent resource IDs, cross-tenant requests) and confirm the original bypass no longer succeeds
- Review - Search the codebase for the same flawed pattern (denylist role checks, ownership-less permission checks) elsewhere
