# CWE-943: Improper Neutralization of Special Elements in Data Query Logic - Go

## LLM Guidance

MongoDB's query format is a document, so an attacker who changes a value's *type* changes the query's structure without changing a character of syntax - `{"password": {"$ne": null}}` matches whatever the stored password is. Where Go differs from the dynamic languages this weakness is usually written up in is the source: `r.URL.Query()` returns `map[string][]string` and does not parse bracket syntax, so `?password[$ne]=null` yields the single literal key `password[$ne]` and the classic query-string payload does nothing. What reaches a filter as a nested document in Go is JSON decoded into `bson.M`, `map[string]interface{}`, or a struct field typed `any`.

## Key Principles

- Decode request bodies into concrete types - a struct of `string`, `int` and `bool` fields - rather than into `bson.M`, `map[string]interface{}`, or `any`, so a scalar cannot arrive as a document
- Build filters from `bson.D` entries the application writes, keeping the choice of field and operator in code and letting the request supply only values
- Look at JSON bodies, CQL strings built with `fmt.Sprintf`, and Lua script text - not at query parameters, which cannot carry a nested document
- Bind CQL values with `?` placeholders and Redis Lua values through `KEYS`/`ARGV`; never concatenate into the script source. `gocql/gocql` has moved to the Apache Software Foundation as `github.com/apache/cassandra-gocql-driver`; the `?` binding syntax is unchanged, but a new project should import the current path rather than the stagnant original
- Stripping `\r`/`\n` from a Redis key defends nothing: RESP is length-prefixed (`$26\r\nuser:123\nDEL important_key\r\n`), so an embedded newline is just data to the protocol parser, not a command separator - a fix that only strips newlines is a no-op
- CQL's `WHERE` grammar is `relation (AND relation)*` - no `OR`, no `UNION` - so a classic `' OR 1=1`/`UNION SELECT` payload is a CQL parse error and proves nothing about whether values are actually bound; test with a value that would change the result set instead
- Keep the password out of the filter: look the user up by name and compare with `bcrypt.CompareHashAndPassword` in application code
- Compare against a fixed dummy hash when no user is found, so an unknown username is not measurably faster than a wrong password
- Allowlist anything that cannot be bound - sort fields, column names, collection names - against a map or slice of permitted values
- Server-side scripting (`$where`, `$function`, `$accumulator` - deprecated in MongoDB 8.0 - and `mapReduce`, deprecated since 5.0) is still enabled by default and still runs; start the server with `--noscripting` where nothing needs it
- Run the application's database account with least privilege so a reshaped query reaches only what the credential permits

## Taint Sinks

`collection.Find()`/`FindOne()`/`UpdateOne()` filter argument, `bson.M` built from decoded JSON, `bson.UnmarshalExtJSON` on request data, `$where`/`mapReduce` given attacker-influenced JavaScript, `aggregate` pipeline stages, `gocql.Session.Query()` built with `fmt.Sprintf`, `redis.Eval()` script text

## Remediation Steps

- Locate - find query calls whose filter or update is built from a decoded request body, and CQL/Lua strings built by formatting
- Trace data flow - follow the decode target: a `bson.M`, a `map[string]interface{}`, or an `any`-typed struct field is where a nested document arrives
- Identify the unsafe pattern - a decoded body used as a filter, a request key used as a field name, or a query built with `fmt.Sprintf`
- Replace with the safe pattern - decode into a typed struct and build the filter with `bson.D{{Key: "username", Value: cleanUsername}}`, not by passing the decoded struct itself as the filter: the driver marshals every declared field, so `User{Username: name}` becomes `{"username": name, "password_hash": "", "role": ""}` and matches nothing
- Break taint after allowlist validation - use the allowlist's own constant for a sort field or column name, not the request's string
- Harden configuration - disable server-side scripting and scope the database user's privileges
- Test - submit `{"$ne": null}`, `{"$gt": ""}` and `{"$regex": ".*"}` in every string field of the JSON body and confirm decoding fails with a 400 rather than the query matching a document
