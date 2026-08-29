# CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key - C#

## LLM Guidance

CWE-566 here is the SQL-primary-key case: a user-controlled ID (route parameter, query string, body property) reaches an EF Core lookup such as `FindAsync()` or a LINQ query, and the row is returned or modified without an ownership filter in the query itself. `FindAsync()` cannot take one - it accepts primary key values only - so the fix there is to replace the call with a filtered query rather than add a condition to it. Everywhere else, put the owning user's ID into the same query.

## Key Principles

- `FindAsync()` has two overloads, `(params object?[] keyValues)` and `(object?[] keyValues, CancellationToken)`, so no predicate can be passed to it and nothing can be chained onto the `ValueTask<TEntity?>` it returns. Replace the call with `FirstOrDefaultAsync(e => e.Id == id && e.UserId == currentUserId)`, an extension from `Microsoft.EntityFrameworkCore`
- Microsoft documents that `Find`/`FindAsync` return an already-tracked entity "immediately without making a request to the database". A predicate expressed as part of the query - a global query filter included - is therefore not evaluated on that path at all, which is the deeper reason the call has to go rather than be filtered
- Put the ownership predicate in the query rather than loading by id and comparing afterwards, so no unauthorized row is materialized and the list endpoint is covered by the same rule
- Take the user id from the claim the app's own authentication actually issues. `FindFirstValue` is an extension method shipped in `Microsoft.Extensions.Identity.Core`, returning `string?`, and `ClaimTypes.NameIdentifier` carries the value only while inbound claim mapping is on - a JWT bearer scheme with `MapInboundClaims = false`, which Microsoft's own bearer configuration sample sets, leaves the raw `sub`. `UserManager.GetUserId(User)` is not a way around that: it reads `Options.ClaimsIdentity.UserIdClaimType`, which defaults to the same `ClaimTypes.NameIdentifier`
- Convert before comparing. Both reads return `string?`, so `e.UserId == currentUserId` does not compile against an `int`, `long` or `Guid` owner column, and a null user id has to fail the request rather than the predicate
- Enforce the rule once at the data access layer with an EF Core global query filter - `modelBuilder.Entity<Order>().HasQueryFilter(o => o.UserId == _currentUserId)` against a value captured on the context instance - so a query written later carries the predicate without anyone remembering it. State its two limits alongside it: `IgnoreQueryFilters()` disables it silently and is common in admin tooling and background jobs, and before EF Core 10 an entity type carries a single filter, so a second concern has to be combined with `&&`; EF Core 10 adds named filters that can be disabled individually
- `ExecuteUpdate`/`ExecuteDelete` (EF Core 7+) are write sinks in their own right. They take effect immediately, never consult the change tracker, and return the number of rows affected - carry the same owner predicate into their `Where`, and treat `0` as the refusal
- Where the identifier is guessable, answering 404 for both the missing and the not-owned row discloses nothing, and under `[ApiController]` both go through `NotFoundResult` and receive the same generated `ProblemDetails` body. Keep `Forbid()` for a gate that does not depend on the record existing and `Challenge()` for an unauthenticated caller, which is the shape Microsoft's own resource-based sample uses; RFC 9110 makes the 404 substitution something a server MAY do, not a rule

## Taint Sinks

`DbSet.Find()`, `DbSet.FindAsync()`, `DbContext.Find()`, `FirstOrDefaultAsync()`, `SingleOrDefaultAsync()`, `ExecuteUpdateAsync()`, `ExecuteDeleteAsync()` - each keyed on a route- or body-bound id with no owner column in the predicate

## Remediation Steps

- Identify user-controlled inputs - route parameters (`[FromRoute]`), query strings (`[FromQuery]`), body properties (`[FromBody]`)
- Trace the id to its lookup and to every write reached by the same value, including `ExecuteUpdate`/`ExecuteDelete` and a `SaveChangesAsync` following an `Attach` or a state change
- Replace `FindAsync(id)` with a filtered query; on a LINQ lookup that already has a predicate, add `&& e.UserId == currentUserId` to it
- Read the user id from the claim type the configured scheme issues, and convert it to the owner column's type before comparing
- Add a global query filter where the ownership rule is application-wide, then audit every `IgnoreQueryFilters()` call against it
- Return `NotFound()` for both the absent and the not-owned row on a guessable identifier
- Test cross-user access with two accounts on every verb, including any nested route (`/api/orders/{orderId}/items/{itemId}`) that loads a child entity without re-checking the parent's owner
