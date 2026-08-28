# CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key - JavaScript

## LLM Guidance

CWE-566 here is the SQL-primary-key case: a route parameter or body ID reaches a SQL ORM call such as Sequelize's `findByPk()`, TypeORM's `findOne({ where: { id } })`, Prisma's `findUnique({ where: { id } })`, or a raw query with the primary key in a `WHERE` clause, and the query returns or modifies the row without an ownership filter in the query itself. The fix belongs in the query - add the owning user's ID to the same `where` condition - not in a separate check performed after the row is fetched. NoSQL document lookups (e.g. Mongoose `findById()`) are the broader CWE-639 case and are out of scope here.

## Key Principles

- Never pass a route or body ID directly to `findByPk()`, `findOne({ where: { id } })`, or `findUnique({ where: { id } })` without also filtering by the owning user's ID in the same query
- Add the ownership condition to the `where` clause itself, e.g. Sequelize `findOne({ where: { id, userId: req.user.id } })` - not as a check performed after the row is fetched
- Read the authenticated user identity from the verified token or session (`req.user.id`), never from the request body
- Return 404 for both non-existent and unauthorized resources to avoid confirming resource existence to attackers
- Apply the same composite filter across all HTTP verbs - GET, PUT, PATCH, and DELETE on the same resource
- Put the ownership predicate in the query itself (an `AND` on the owner column, or the ORM's equivalent) rather than fetching by id and comparing the returned row afterwards

## Taint Sinks

Sequelize `Model.findByPk()`, `Model.findOne({ where: { id } })`; TypeORM `repository.findOne({ where: { id } })`; Prisma `prisma.model.findUnique({ where: { id } })`; raw SQL `SELECT ... WHERE id = ?` - all on `req.params.id`/`req.body.id` without a composite user-scoped filter

## Remediation Steps

- Locate route parameters used as resource identifiers (`req.params.id`, `req.params.orderId`, etc.)
- Trace them to SQL ORM or query calls - `findByPk()`, `findOne({ where: { id } })`, `findUnique({ where: { id } })`, or raw SQL keyed on the primary key alone
- Add the owning user's ID to the same query condition, not as a follow-up check after retrieval
- Ensure `req.user` is set by authentication middleware that runs before the handler
- Return `res.sendStatus(404)` (not 403) when the resource doesn't exist or is not owned by the user
- Carry the same composite `where` into write paths - Sequelize `Model.destroy({ where: { id, ownerId } })` and `update()` - and allowlist the body fields applied on update
- Test by authenticating as one user and requesting another user's resource IDs
