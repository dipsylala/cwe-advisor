# CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key - Java

## LLM Guidance

CWE-566 here is the SQL-primary-key case: a user-controlled ID (`@PathVariable`, `@RequestParam`) reaches a Spring Data JPA / Hibernate lookup via `findById()`, and the row is returned or modified without an ownership filter in the query itself. The fix belongs in the repository query - a derived `findByIdAndUserId()`, an explicit `WHERE id = ? AND user_id = ?`, or the current user injected into the query - rather than a post-fetch comparison in application code, which is easy to omit on another code path and easy to get wrong when the two types differ.

## Key Principles

- Declaring the composite method on the repository interface is the whole change: under the default `CREATE_IF_NOT_FOUND` lookup strategy Spring Data derives `Optional<Order> findByIdAndUserId(Long id, Long userId)` at bootstrap, with no `@Query` and no implementation, and it does not collide with the inherited `findById`
- Know which property the derived name binds to. Spring Data tries `userId` whole first, then splits the name from the right - so on an entity with a `@ManyToOne User user` and no scalar column it resolves to `user.id`, while on one carrying both it binds to the scalar. `findByIdAndUser_Id` makes the traversal explicit, which is the vendor's own disambiguation syntax
- `@AuthenticationPrincipal` does not yield a numeric id by default: the principal is a `UserDetails`, whose only identity is `getUsername()`, a `String`. Customise the principal to carry an id or read it with `@AuthenticationPrincipal(expression = "...")` - and note `errorOnInvalidType` defaults to `false`, so declaring a custom type that is not the configured one injects `null` rather than failing
- Compare like types - a `Long` owner column against a username `String` is the concrete form of that mismatch, and it denies or matches wrongly while reading as correct
- Spring Security can put the current user into the query itself: add `org.springframework.security:spring-security-data`, expose a `SecurityEvaluationContextExtension` bean, and write `@Query("select o from Order o where o.user.id = ?#{ principal?.id }")`. The vendor's stated reason for preferring this to a post-fetch filter is that filtering afterwards does not scale to paged results
- A Hibernate `@Filter` needs a qualifier before it covers this CWE at all: the vendor states that by default "a filter does not apply to lookups by primary key", naming `find()` - which is what `findById()` performs. `@FilterDef(applyToLoadByKey = true)` covers that path and exists only from Hibernate **6.6**; `autoEnabled`, which removes the per-session `Session.enableFilter` call, arrived in **6.5**
- `findById()` is the framework's own retrieval API, inherited by every `CrudRepository`, so its presence is not the finding - the absent owner predicate is. It also cannot be withdrawn while extending `JpaRepository`; the documented route is a `@NoRepositoryBean` base interface declaring only the methods you mean to expose
- Apply the same composite filter to every path reaching the row - `deleteById`, `findAllById` and `deleteAllById` included - and note that a bulk JPQL `DELETE`/`UPDATE` runs straight against the database without consulting the persistence context, so no entity callback can re-check ownership there
- `getOne` and `getById` are deprecated in favour of `getReferenceById` (Spring Data JPA 2.7). All three return a lazy reference, so the predicate has to be in the query that loads it
- Answering "not yours" as a 404 has no built-in mechanism. `ExceptionTranslationFilter` sends an authenticated caller's `AccessDeniedException` to `AccessDeniedHandlerImpl`, which emits 403, and an anonymous caller's to the `AuthenticationEntryPoint` instead. A `@RestControllerAdvice` `@ExceptionHandler` returning `ResponseEntity.notFound()` is the usual form - scope it to this check's own exception rather than to every `AccessDeniedException`, since collapsing all of them also hides the missing-scope and CSRF failures that should stay 403

## Taint Sinks

`repository.findById()`, `repository.getReferenceById()`, `getOne()`, `getById()`, `findAllById()`, `deleteById()`, `deleteAllById()`, `entityManager.find()`, and JPQL/native queries whose `WHERE` names the primary key alone - each on a `@PathVariable`/`@RequestParam` id with no owner condition in the same query

## Remediation Steps

- Locate user-controlled inputs (`@PathVariable`, `@RequestParam`) used as resource identifiers
- Trace each to repository or query methods keyed on the primary key alone, including the delete and bulk paths
- Add a composite repository method (`findByIdAndUserId`) or a `WHERE ... AND user_id = ?` clause, and confirm the derived name resolves to the property you intend
- Obtain the user id from a principal that actually carries one, and convert it to the owner field's type before comparing
- Replace any fetch-then-check application code with the query-level filter
- Where the rule is application-wide, prefer the Spring Data SpEL form, or a Hibernate filter declared with `applyToLoadByKey = true`, over repeating the predicate at every call site
- Test with different authenticated users attempting to reach each other's resources by ID, on `GET`, `PUT` and `DELETE`
