# CWE-943: Improper Neutralization of Special Elements in Data Query Logic - Java

## LLM Guidance

NoSQL injection in Java needs a hole to come through: a parameter typed `Object`, a `@RequestBody Map<String, Object>`, or a `Document` accepted straight from a request. Declare the types you expect and the binder enforces them - a DTO of `String`, `int` and `boolean` fields closes the hole before any query code runs, because Jackson rejects an object where a `String` was declared. Build filters with the driver's `Filters` class or Spring Data's `Criteria` so the field and the operator are chosen in code and the request supplies only values.

## Key Principles

- Bind request bodies to a typed DTO rather than `Map<String, Object>`, `Document`, or a field typed `Object` - that is where the operator document arrives
- Where a map is genuinely required, allowlist the keys and check each value with `isInstance` on the path that builds the query
- Build the filter with `Filters.eq("username", cleanUsername)` or a Spring Data `Criteria`, never by deserializing a request into a `Document` and passing it as the filter
- Keep the password out of the filter: look the user up by name and verify the hash with `BCryptPasswordEncoder.matches` in application code, constructing the encoder with an explicit strength (`new BCryptPasswordEncoder(12)`)
- Compare against a fixed dummy hash when no user is found, so an unknown username is not measurably faster than a wrong password
- Validate free-form identifiers with an anchored pattern (`Pattern.compile("[a-zA-Z0-9_]{3,50}")` plus `matches()`, which is whole-string in Java) before they reach a query
- Allowlist sort fields, projections and collection names against a fixed `Set`; those cannot be bound as values
- Never enable `$where`, `$function` or `mapReduce`, and never build an aggregation pipeline stage from request data
- Run the application's database account with least privilege so a reshaped query reaches only what the credential permits

## Taint Sinks

`MongoCollection.find()`/`updateOne()` with a request-derived `Document`, `Document.parse()` on request JSON, `MongoTemplate.find()` with a `BasicQuery` built from a string, `Criteria` built from request keys, `aggregate()` pipeline stages, `$where` expressions

## Remediation Steps

- Locate - find query calls whose filter or update is built from a `Map`, a `Document`, or an `Object`-typed parameter reaching a controller
- Trace data flow - follow the request body from binding through any map merge into the filter, noting where a nested object could stand in for a scalar
- Identify the unsafe pattern - a request-supplied document used as a filter, a request key used as a field name, or a `BasicQuery` built by concatenation
- Replace with the safe pattern - introduce a typed DTO, and build the filter with `Filters`/`Criteria` using literal field names
- Break taint after allowlist validation - use the allowlist's own constant for the field name, not the request's string
- Harden configuration - disable server-side JavaScript on the server and scope the application's database user
- Test - submit `{"$ne": null}`, `{"$gt": ""}` and `{"$regex": ".*"}` in every string field and confirm binding fails with a 400 rather than the query matching a document
