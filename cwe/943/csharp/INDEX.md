# CWE-943: Improper Neutralization of Special Elements in Data Query Logic - C#

## LLM Guidance

NoSQL injection in .NET arrives through a weakly typed binding target: a `Dictionary<string, object>` or `BsonDocument` bound from a request body accepts an operator document where a scalar was expected. Bind to a DTO whose properties are `string`, `double` and `bool` so the model binder rejects it before any query code runs, and build filters with `Builders<T>.Filter` against a POCO collection so the field and the operator stay in code and the request supplies only values.

## Key Principles

- Bind request bodies to a typed DTO, never to `Dictionary<string, object>`, `BsonDocument`, or a property typed `object`
- Build MongoDB filters with `Builders<AppUser>.Filter.Eq(u => u.Username, cleanUsername)` against a typed collection - the lambda fixes the field name at compile time
- Parameterize Cosmos DB with `QueryDefinition.WithParameter` and RavenDB with `AddParameter`; never concatenate request values into the query text
- Allowlist what the driver cannot bind - sort columns, container and collection names, attribute names - against a fixed `HashSet`
- Keep the password out of the filter: look up by username and verify with `IPasswordHasher<T>.VerifyHashedPassword` in application code, running the verify against the decoy hash on the not-found path so an unknown username is not measurably faster
- Generate the decoy hash at startup with the configured hasher rather than pasting a literal - ASP.NET Identity reads the iteration count out of the stored hash, so a literal keeps costing whatever it was minted at when `IterationCount` is raised
- Never enable `$where`/`$function`/`mapReduce`, and never build an aggregation pipeline stage from request data
- Run the application's database account with least privilege so a reshaped query reaches only what the credential permits

- `$regex` is a sink in its own right, not just a probe: an attacker-supplied pattern runs on the
  MongoDB server under its own engine, so nothing configured in the application's regex library
  applies. Escape the term before it becomes a pattern - `re.escape`, `Pattern.quote`, `Regex.Escape` -
  or match exactly instead
- Watch the failure direction when a filter is built conditionally: silently dropping a condition that
  could not be validated leaves the query *wider* than the caller asked for, and an endpoint that has
  quietly stopped filtering still answers 200

## Taint Sinks

`IMongoCollection.Find()` with a request-derived `BsonDocument`, `BsonDocument.Parse()` on request JSON, `FilterDefinition` built from a JSON string, `QueryDefinition` built by string concatenation, `aggregate` pipeline stages, `$where` expressions

## Remediation Steps

- Locate - find query calls whose filter or query text is built from a request body, query string, or route value
- Trace data flow - follow the bound model into the filter, noting any `object`/`dynamic`/`BsonDocument` on the path where a nested document could arrive
- Identify the unsafe pattern - a request-supplied document used as a filter, a request key used as a field name, or a query string built by interpolation
- Replace with the safe pattern - introduce a typed DTO and build the filter with `Builders<T>.Filter` and property lambdas
- Break taint after allowlist validation - use the allowlist's own constant for a sort column or container name, not the request's string
- Harden configuration - disable server-side JavaScript on the database and scope the application's account
- Test - submit `{"$ne": null}`, `{"$gt": ""}` and `{"$regex": ".*"}` in every string field and confirm model binding fails with a 400 rather than the query matching a document
