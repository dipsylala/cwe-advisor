# CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key - Java

## LLM Guidance

CWE-566 here is the SQL-primary-key case: a user-controlled ID (`@PathVariable`, `@RequestParam`) reaches a Spring Data JPA / Hibernate query via `findById()`, and the row is returned or modified without an ownership filter in the query itself. The fix belongs in the repository query - use a method like `findByIdAndUserId()`, or an explicit `WHERE id = ? AND user_id = ?` in a JPQL/native query - not a post-fetch comparison in application code, which is easy to omit on other code paths and easy to get wrong (mismatched types silently deny or allow access).

## Key Principles

- Never trust a user-supplied primary key value as sufficient proof of authorization
- Filter the query itself by both the primary key and the owning user's ID (e.g. `findByIdAndUserId(orderId, userId)`) - do not fetch by ID alone and compare ownership afterward
- Define repository methods that return rows already scoped to the current user; avoid exposing a bare `findById()` for user-facing resources
- Apply the same composite filter consistently across read, update, and delete operations
- Compare like types when building the filter - the owner ID column type must match the authenticated user ID type (e.g. `Long` to `Long`), not a numeric ID against a `Principal`/`Authentication` username string
- `@PreAuthorize("isAuthenticated()")` proves only that someone is logged in - the ownership predicate has to name the record, and `orElseThrow()` on a repository lookup by id alone enforces nothing
- Throw `AccessDeniedException` and map it to the same response as "not found", and apply the check on `DELETE` and `PUT` as well as `GET`

## Taint Sinks

`repository.findById()` used alone on a `@PathVariable`/`@RequestParam` ID, without a composite `findByIdAndUserId()` method or `WHERE ... AND user_id = ?` clause

## Remediation Steps

- Locate user-controlled inputs (`@PathVariable`, `@RequestParam`, `@PathParam`) used as resource identifiers
- Trace the data flow to repository or query methods keyed on the primary key alone (`findById()`, or JPQL/native queries without a `user_id` condition)
- Add a composite repository method (`findByIdAndUserId`) or `WHERE` clause that filters by both the ID and the authenticated user's ID, taken from `@AuthenticationPrincipal`
- Replace any fetch-then-check application code with the query-level filter
- Confirm the identifier type used in the filter matches the entity's owner field type
- Test with different authenticated users attempting to access each other's resources by ID
