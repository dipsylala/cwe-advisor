# CWE-943: Improper Neutralization of Special Elements in Data Query Logic - Python

## LLM Guidance

NoSQL injection in Python happens when a decoded request body is handed to a query: a JSON body arrives already typed, so `{"username": {"$ne": None}}` becomes a filter operator rather than a value. PyMongo has no parameterization and no sanitizing layer, so the whole defence is requiring the type each value must have on the code path that builds the filter, and building the filter dictionary in code so the request supplies values and the application supplies every key and operator.

## Key Principles

- The right check depends on where the value came from: a JSON body arrives typed, so `isinstance(value, str)` is the test and anything else is a 400; a query string arrives as text, so `int(raw)`/`float(raw)` is the test, because it either produces the type or raises
- Do not use `str(value)` to "sanitise" a field that should be a string - it coerces rather than rejects, turning `{"$ne": None}` into the literal `"{'$ne': None}"` and searching for a username nobody has instead of reporting the problem
- Allowlist anything that names a field rather than supplying a value: filter fields, sort targets, projections
- `mongoengine`'s keyword-argument queries are the ODM equivalent of building the filter in code; `__raw__` opts back out of it
- Keep the password out of the filter: look the user up by name and compare the hash with `bcrypt.checkpw` in application code, so no operator can match a document without knowing the secret
- Compare against a fixed dummy hash when no user is found, so an unknown username is not measurably faster than a wrong password
- Disable server-side JavaScript rather than declining to enable it: `$where`, `$function`,
  `$accumulator` and `mapReduce` all execute it and are on by default, so the action is
  `security.javascriptEnabled: false` (or `--noscripting`). MongoDB deprecated map-reduce in 5.0 and
  the JavaScript operators in 8.0, and names `$expr` as the non-JavaScript replacement. Never build an
  aggregation pipeline stage from request data
- Redis: build key names from validated components, and pass request data to `eval` as `KEYS`/`ARGV` arguments rather than as script text
- Run the application's database account with least privilege, so a reshaped query reaches only what the credential permits

- `$regex` is a sink in its own right, not just a probe: an attacker-supplied pattern runs on the
  MongoDB server under its own engine, so nothing configured in the application's regex library
  applies. Escape the term before it becomes a pattern - `re.escape`, `Pattern.quote`, `Regex.Escape` -
  or match exactly instead
- Watch the failure direction when a filter is built conditionally: silently dropping a condition that
  could not be validated leaves the query *wider* than the caller asked for, and an endpoint that has
  quietly stopped filtering still answers 200

## Taint Sinks

`collection.find()`/`find_one()`/`update_one()` filter argument, `aggregate()` pipeline, `$where` expressions, `mongoengine` `__raw__`, `redis.eval()`, `boto3` DynamoDB `FilterExpression`/`ExpressionAttributeValues`

## Remediation Steps

- Locate - find query calls whose filter, update document, or pipeline is built from `request.json`, `request.form`, `request.args`, or `request.data`
- Trace data flow - follow the value through any dict merge, `**kwargs` spread, or reassignment into the filter, noting where a dict could arrive in place of a scalar
- Identify the unsafe pattern - a request value used directly as a filter value, a request key used as a filter key, or a decoded body passed as the filter itself
- Replace with the safe pattern - validate each value's type with `isinstance` (or a constructor that raises), then build the filter dict in code with literal keys
- Break taint after allowlist validation - use the allowlist's own field-name constant as the query key, not the request's string
- Harden configuration - disable server-side JavaScript on the database, and scope the application's database user
- Test - submit `{"$ne": null}`, `{"$gt": ""}`, `{"$regex": ".*"}` in every string field and confirm each is rejected with a 400 rather than matching a document. A `$where` payload does not belong in this list: it is a top-level query operator and does not execute inside a nested document, so submitting one as a field *value* proves nothing either way - test that one only where the code splices a value into a `$where` expression
