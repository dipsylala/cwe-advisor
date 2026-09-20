# CWE-285: Improper Authorization

## LLM Guidance

Where the check is absent altogether the entry is CWE-862, where it exists and its logic is wrong CWE-863, and where a user-controlled key reaches the record with no ownership test, CWE-639 - or CWE-566 for the SQL primary-key case. Use this entry for the general authorization failure that fits none of those.

## Key Principles

- Never infer authorization from authentication, role, or prior checks alone
- Every security-sensitive action must be explicitly authorized against the specific resource and operation
- Authorization checks must occur server-side and cannot be bypassed by client manipulation
- Use centralized authorization logic to ensure consistent enforcement across the application
- Default to deny: require explicit permission grants rather than assuming access
- Check both levels: that the caller may invoke the function *and* that they may act on the specific object. An object-level hook never fires on a collection endpoint, so the list, search, export and bulk routes over the same data are the ones usually left bare - and they return more rows per request than the route that gets flagged
- Make the two denials indistinguishable - "not yours" and "does not exist" must return the same status and the same body, or the pair enumerates the table one request at a time
- Let one place decide the whole question. A missing-record check placed ahead of the authorization call answers 404 for an unknown id and 403 for someone else's, rebuilding the enumeration oracle the ownership check exists to close - and it answers first, so it responds even to a caller the authorization would have refused outright
- Re-verify at each step of a multi-step flow rather than trusting that an earlier step authorized the identifier being carried forward; a request that jumps straight to the later step passes no check at all
- Test the accept side first: a control that refuses everyone passes every rejection assertion identically, and that is the most common way an authorization fix ships broken

## Remediation Steps

- Review flaw details to identify the specific file, line number, and vulnerable code pattern
- Identify the protected resource or operation lacking authorization checks
- Trace the data flow to determine if ANY authorization check exists before the operation
- Implement explicit permission checks for every request that accesses protected resources
- Validate that the current user owns or has explicit access to the specific resource being accessed
- Treat the reported line as a sample of the population rather than the population: find the other routes reaching the same data and fix them in the same pass
- Use established authorization frameworks or patterns rather than custom logic where possible
