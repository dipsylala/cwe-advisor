# CWE-943: Improper Neutralization of Special Elements in Data Query Logic - JavaScript

## LLM Guidance

NoSQL injection in Node.js happens when a decoded request body reaches a query filter, because an Express body parser will hand you an object wherever the code expected a string - `{"username": {"$ne": null}}` becomes a filter operator rather than a value. The fix is to check that every value entering a filter is a primitive (`typeof x === 'string' | 'number'`) on the code path that builds the query, allowlist any request field that names a *field* rather than supplying a value, and build the filter object in application code so keys and operators are literals.

## Key Principles

- A Mongoose schema does not protect a query: schema types cast and validate *documents*, not filters, so `Model.findOne({ username: { $ne: 'admin' } })` reaches MongoDB intact on a `strict: true` schema. The control that applies to filters is `mongoose.set('sanitizeFilter', true)`, which is off by default
- Validate with `typeof` and reject, rather than coercing with `String(value)` - coercion turns an injection attempt into a wrong-but-quiet lookup instead of an error
- Keep secrets out of the filter entirely: look the user up by name, then compare the password hash with `bcrypt.compare` in application code, so no operator can match a document without knowing the password
- Compare against a fixed dummy hash when the user is not found, so an unknown username does not return measurably faster than a wrong password
- Allowlist field names, sort targets and projections against a fixed `Set`; never spread request data into a filter, an `$or` array, or an aggregation pipeline
- Reject keys beginning with `$` and containing `.` anywhere a request-supplied object is unavoidable (`express-mongo-sanitize` does this globally, as a backstop rather than the fix)
- Never enable `$where`, `mapReduce`, or `$function`, whose expressions execute server-side JavaScript
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
- Test - submit `{"$ne": null}`, `{"$gt": ""}`, `{"$regex": ".*"}` and a `$where` payload in every string field, and confirm each is rejected with a 400 rather than matching a document
