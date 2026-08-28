# CWE-943: Improper Neutralization of Special Elements in Data Query Logic - JavaScript

## LLM Guidance

NoSQL injection in Node.js happens when a decoded request body reaches a query filter, because an Express body parser will hand you an object wherever the code expected a string - `{"username": {"$ne": null}}` becomes a filter operator rather than a value. The fix is to check that every value entering a filter is a primitive (`typeof x === 'string' | 'number'`) on the code path that builds the query, allowlist any request field that names a *field* rather than supplying a value, and build the filter object in application code so keys and operators are literals.

## Key Principles

- A Mongoose schema is not a filter-injection defence, though not for the reason usually given:
  Mongoose does cast the filter to the schema, and a value it cannot cast raises `CastError`. What it
  does not do is reject a *castable operator object*, so `{ username: { $ne: 'admin' } }` still
  reaches MongoDB. By default it also leaves filter properties that are not in the schema alone -
  `strictQuery: true` strips them and `'throw'` rejects them
- The control aimed at this is `mongoose.set('sanitizeFilter', true)` (Mongoose 6.0 and later), off by
  default, which wraps any nested object with a `$`-prefixed property in `$eq`. It does not address
  attacker-controlled *keys*, `$where` strings, or aggregation pipelines - Mongoose does not cast
  pipelines at all. `mongoose.trusted()` is the documented way to let a genuine operator through
- Validate with `typeof` and reject, rather than coercing with `String(value)` - coercion turns an injection attempt into a wrong-but-quiet lookup instead of an error
- Keep secrets out of the filter entirely: look the user up by name, then compare the password hash with `bcrypt.compare` in application code, so no operator can match a document without knowing the password
- Compare against a fixed dummy hash when the user is not found, so an unknown username does not return measurably faster than a wrong password
- Allowlist field names, sort targets and projections against a fixed `Set`; never spread request data into a filter, an `$or` array, or an aggregation pipeline
- Reject keys beginning with `$` and containing `.` anywhere a request-supplied object is unavoidable (`express-mongo-sanitize` does this globally, as a backstop rather than the fix)
- Disable server-side JavaScript rather than declining to enable it: `$where`, `$function`,
  `$accumulator` and `mapReduce` all execute it and are available by default, so the action is
  `security.javascriptEnabled: false` (or `--noscripting`) on the server. MongoDB deprecated
  map-reduce in 5.0 and the JavaScript operators in 8.0; `$expr` is its named non-JavaScript
  replacement for most `$where` uses
- Redis: build key names from validated components, and never pass request data into `EVAL` as script text - pass it as a `KEYS`/`ARGV` argument
- Run the application's database account with least privilege, so a reshaped query reaches only what the credential permits

## Taint Sinks

`collection.find()`/`findOne()`/`updateOne()` filter argument, `Model.find()`/`findOne()` in Mongoose, `aggregate()` pipeline stages, `$where`/`$function`/`mapReduce`, `redis.eval()`, `deleteMany()` filter

## Remediation Steps

- Locate - find query calls whose filter, update, or pipeline is built from `req.body`, `req.query`, or `req.params`
- Trace data flow - follow the value through any spread, `Object.assign`, or merge into the filter object, noting where an object could arrive in place of a scalar
- Identify the unsafe pattern - a request value used directly as a filter value, a request key used as a filter key, or a request-supplied object spread into a query
- Replace with the safe pattern - validate each value's `typeof`, build the filter literal in code, and pass only validated primitives
- Break taint after allowlist validation - use the allowlist's own field-name constant for the query key, not the request's string
- Harden configuration - enable `sanitizeFilter` in Mongoose, disable server-side JavaScript execution on the server, and scope the database user's privileges
- Test - submit `{"$ne": null}`, `{"$gt": ""}`, `{"$regex": ".*"}` in every string field, and confirm each is rejected with a 400 rather than matching a document. Leave `$where` out of that list: it is a top-level query operator and does not execute inside a nested document, so submitting one as a field value proves nothing. Check the Express version too - Express 4 and 5 parse `username[$ne]` differently, so the same probe can mean different things
