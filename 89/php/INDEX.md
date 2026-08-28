# CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - PHP

## LLM Guidance

SQL Injection occurs when untrusted data is incorporated into SQL queries without proper parameterization, allowing attackers to manipulate queries to bypass authentication, access unauthorized data, or execute administrative operations.

**Primary Defence:** Use prepared statements with PDO or MySQLi, or modern ORMs like Laravel Eloquent that use prepared statements internally. Escape functions alone are insufficient and must not be relied upon.

## Key Principles

- Always use prepared statements with bound parameters for all SQL queries containing user input
- Employ parameterized queries through PDO or MySQLi, never string concatenation
- Use ORMs (Laravel Eloquent, Doctrine) that handle parameterization automatically
- Apply input validation as a secondary defence layer, but never as the primary protection
- Reject escape functions (mysql_real_escape_string) as the sole defence mechanism
- Bind `LIKE` wildcard values as a parameter too - concatenating `"%$search%"` into an otherwise-prepared query still injects the wildcard portion
- Treat `PDO::quote()` as manual escaping, not parameterization - it builds a string for you to concatenate and is easy to misuse; prefer bound parameters
- `prepare()` plus `bindValue()`/`execute([...])` is the fix; `mysqli_real_escape_string()` and `pg_escape_string()` are escaping functions that do nothing for an unquoted numeric context and depend on the connection's charset being set correctly
- PostgreSQL's `pg_query_params()` is the parameterized form for the pgsql extension - use it rather than interpolating with `sprintf()`
- In Laravel, `whereRaw()`/`selectRaw()`/`orderByRaw()` are the raw sinks and take bindings as a second argument; `whereIn()` binds each element, while a hand-built `IN` list does not
- An identifier - a table, a column, an `ORDER BY` direction - cannot be bound and needs allowlist validation against a fixed set

## Taint Sinks

`mysqli_query()`, `mysqli::query()`, `PDO::query()`, `PDO::exec()`

## Remediation Steps

- Locate the sink (SQL execution point) and source (user input) in the data flow report
- Trace how data flows from source to sink, identifying any concatenation or interpolation
- Replace concatenated queries with prepared statements using PDO or MySQLi
- Bind all user-supplied values as parameters, never interpolate them into query strings - with MySQLi, `bind_param()` takes a leading type-character string (for example `"ss"`) matching the placeholders in order
- Validate input types and formats as secondary defence (e.g., verify IDs are numeric)
- Test the fix by attempting injection attacks and reviewing query logs
