# CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key

## LLM Guidance

CWE-566 is the SQL-specific case of Insecure Direct Object Reference (see CWE-639): a user-controlled value is used directly as, or to build, the primary key in a SQL query, and the query returns or modifies the matching row without verifying the authenticated user owns or may access that record. Unlike the broader CWE-639, the fix here is scoped to the query itself, not just an application-layer check. Core fix: add an ownership/authorization condition to the query so it cannot return another user's row even if an upstream check is bypassed.

## Key Principles

- Never trust a user-supplied primary key value as sufficient proof of authorization to access that row
- Add an ownership condition to the query itself (filter by both the primary key and the authenticated user's ID), rather than checking ownership separately after the fact
- Enforce this at the data access layer so no code path can query by primary key without the ownership filter
- Return the same status and body for "no such key" and "not your key" - any difference between the two reveals which keys exist
- Consider indirect or session-scoped references where the identifier exposed to the client does not map directly to the database primary key
- Scope the query itself to the authenticated user rather than loading the row and checking ownership afterwards - the predicate then prevents returning another user's data, and there is no window in which unauthorized data is held in memory
- Nothing in the query looks wrong, which is why this survives review: `get(id)` returns the row with that key exactly as written, and what is absent is any statement that the caller is entitled to it
- Apply the check on every operation, not only reads - update and delete paths reached by the same identifier are the ones usually left behind

## Remediation Steps

- Trace data flow - Identify where a user-controlled value (URL parameter, form field, API path segment) reaches a SQL query as the lookup value for a primary key
- Locate the query construction - Find selects/updates/deletes by primary key alone, without a condition tied to the authenticated user
- Add ownership enforcement - Modify the query to filter on both the primary key and an ownership/tenant column scoped to the current session
- Avoid fixing only at the application layer - Ensure the query itself cannot return another user's row even if an upstream authorization check is bypassed
- Implement consistent responses - Answer a key that matches no row and a key belonging to another user identically, since 403 for one and 404 for the other tells the caller which keys are real. Where the identifier is guessable, 404 for both is the form that discloses nothing; reserve 403 for a gate that does not itself depend on the record existing
- Test thoroughly - Attempt cross-user access with different accounts, substituting a valid primary key value belonging to a different account
