# CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key - C#

## LLM Guidance

CWE-566 here is the SQL-primary-key case: a user-controlled ID (route parameter, query string) reaches an EF Core query via `FindAsync()` or a LINQ lookup, and the query returns or modifies the row without an ownership filter in the query itself. The fix belongs in the query - add a `.Where(e => e.UserId == currentUserId)` condition (or equivalent) to the same query - not a separate ownership check performed after the entity is retrieved.

## Key Principles

- Never trust user-supplied resource identifiers without authorization checks
- Filter queries by authenticated user ID in the query itself - do not fetch by primary key alone and check ownership afterward
- Implement centralized authorization policies using ASP.NET Core Authorization or repository patterns
- Use strongly-typed claims (`ClaimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier)`) to get authenticated user context
- Return 404 instead of 403 for unauthorized resources to avoid information disclosure
- Put the ownership predicate in the query (`&& d.UserId == currentUserId`) rather than loading by id and comparing afterwards, so no unauthorized row is materialized and the list endpoint is covered by the same rule

## Taint Sinks

`FindAsync()`, `FirstOrDefaultAsync()`, LINQ queries on route/query-bound IDs without a `.Where(e => e.UserId == currentUserId)` filter

## Remediation Steps

- Identify user-controlled inputs - route parameters (`[FromRoute]`), query strings (`[FromQuery]`), request body properties
- Trace the ID to database queries (`FindAsync`, `FirstOrDefaultAsync`, LINQ) lacking user filters
- Extract authenticated user ID from `User.FindFirstValue(ClaimTypes.NameIdentifier)`
- Add authorization check - filter queries with `.Where(e => e.UserId == currentUserId)` in the query itself, not as a check performed after retrieval
- Return `NotFound()` if entity doesn't exist or user lacks access
- Apply authorization attributes (`[Authorize]`) and consider policy-based authorization for complex scenarios
