# CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key - JavaScript

## LLM Guidance

CWE-566 here is the SQL-primary-key case: a route parameter or body ID reaches a SQL ORM call such as Sequelize's `findByPk()`, TypeORM's `findOne({ where: { id } })`, Prisma's `findUnique({ where: { id } })`, or a raw query with the primary key in a `WHERE` clause, and the query returns or modifies the row without an ownership filter in the query itself. The fix belongs in the query - the owning user's ID goes into the same `where` condition rather than into a check performed after the row is fetched - but two of those calls will not accept one as written, so establish which call you are editing before adding a key to it. NoSQL document lookups (e.g. Mongoose `findById()`) are the broader CWE-639 case and are out of scope here.

## Key Principles

- Sequelize's `findByPk()` cannot carry an ownership filter. Its documentation states `Note that options.where is not supported`, and the implementation assigns `options.where = { [primaryKeyAttribute]: param }` over whatever was passed. A filter handed to it runs, enforces nothing and raises no error - replace the call with `findOne({ where: { id, userId } })` rather than adding an option to it
- Prisma's `findUnique()` accepts a non-unique field such as `userId` alongside the unique one only from **5.0.0**, where the `extendedWhereUnique` feature reached GA; 4.5.0 through 4.x carry it behind `previewFeatures = ["extendedWhereUnique"]`. Below that floor the composite form is a TypeScript error and a `PrismaClientValidationError` at runtime. `findFirst({ where: { id, userId } })` has no such restriction at any version and is the safer rewrite
- A compound `@@unique([userId, id])` changes the shape rather than adding a key: the generated input nests under the constraint name, as `where: { userId_id: { userId, id } }`
- TypeORM takes the composite filter as either `findOne({ where: { id, userId } })` or `findOneBy({ id, userId })`. The bare `findOne(id)` form was dropped in 0.3.0 in favour of `findOneBy`, so an audit that greps only for `findOne` misses every call site migrated to 0.3
- Read the authenticated user identity from the verified token or session (`req.user.id`), never from the request body
- Apply the same composite filter across every verb, and carry it into the batch paths, which no single-row fix touches - Prisma `updateMany`/`deleteMany`, Sequelize `Model.update`/`Model.destroy`
- Sequelize reports a write as a count rather than a row: `destroy()` resolves to the number of rows deleted and `update()` to an array whose first element is the number matched. A composite `where` matching nothing resolves successfully with `0`, so the handler has to read that count to answer at all
- An eager load runs its own query and is not scoped by the parent's filter - a Sequelize `include`, a TypeORM `relations`, or a Prisma `include` on a related model can return another user's linked record from an otherwise correctly filtered lookup
- Enforce the rule once where the ORM supports it: a Prisma Client extension (`$extends`, GA in 4.16.0) hooks the query life-cycle through its `query` component, and Prisma ships a `row-level-security` reference extension pairing that with Postgres policies

## Taint Sinks

Sequelize `Model.findByPk()`, `Model.findOne({ where: { id } })`, `Model.update()`, `Model.destroy()`; TypeORM `repository.findOne({ where: { id } })`, `repository.findOneBy({ id })`; Prisma `prisma.model.findUnique({ where: { id } })`, `findFirst()`, `updateMany()`, `deleteMany()`; raw SQL `SELECT ... WHERE id = ?` - each on `req.params.id`/`req.body.id` with no owner column in the same condition

## Remediation Steps

- Locate route and body parameters used as resource identifiers (`req.params.id`, `req.params.orderId`, `req.body.orderId`)
- Trace each to its ORM or raw query, on the read path and on every update, delete and batch call reached by the same identifier
- Rewrite, rather than parameterise, the calls that cannot take the predicate: `findByPk(id)` becomes `findOne({ where: { id, userId } })`, and `findUnique` below Prisma 5.0 becomes `findFirst`
- Add the owning user's ID to the same query condition everywhere else, not as a follow-up check after retrieval
- Confirm `req.user` is populated before the handler runs: Express executes middleware in registration order, so a router mounted before the authentication middleware is registered runs with `req.user` undefined and the ownership predicate compares against nothing
- Read the affected-row count on write paths and treat `0` as the refusal rather than reporting success
- Return `res.sendStatus(404)` for both the unknown and the not-owned key where the identifier is guessable - it sends the registered status message as the body, so both answers match in body as well as status
- Test by authenticating as one user and requesting another user's resource IDs, on every verb and on any batch endpoint over the same table
