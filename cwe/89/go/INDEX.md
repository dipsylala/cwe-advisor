# CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Go

## LLM Guidance

Go's `database/sql` supports safe parameterization through placeholders (`?` for MySQL/SQLite, `$1`/`$2` for PostgreSQL), but raw SQL built with string concatenation or `fmt.Sprintf` is common because Go has no implicit ORM layer. The primary remediation is passing every user-controlled value as an argument to `db.Query`/`db.Exec`/`db.QueryRow` rather than interpolating it into the query text; identifiers such as column names and sort direction cannot be parameterized and require allowlist validation instead.

## Key Principles

- Use `database/sql` placeholders for all data values: `db.Query(query, arg1, arg2)`, never `fmt.Sprintf` or `+` into the SQL string
- With ORMs (GORM, sqlx), use their parameterized query builders (`Where("x = ?", v)`, `NamedQuery`).
  `db.Raw` is not the only sink to check: GORM's own security documentation lists `Select`,
  `Distinct`, `Pluck`, `Group`, `Order`, `Table`, `Joins` and `Exec` as methods that do not escape
  their input. `Order` matters most here, since it is exactly where a user-chosen sort column lands
  after the value parameters have been dealt with. `Raw` and `Exec` given `?` arguments are safe -
  what makes them a finding is a concatenated string, not the call itself
- SQL identifiers (table/column names, `ORDER BY` direction) cannot be bound as parameters; validate them against a Go map or allowlist before use
- Keep placeholder-numbering helpers (`fmt.Sprintf("$%d", n)`) restricted to generating placeholder syntax only, never to inserting the value itself
- Scan results with typed `Scan()`/`StructScan()` destinations rather than feeding returned data into further queries without revalidation
- Apply least-privilege database credentials as defence-in-depth

## Taint Sinks

`db.Query()`, `db.Exec()`, `db.QueryRow()`, `gormDB.Raw()`, `sqlx.NamedQuery()` with concatenated SQL

## Remediation Steps

- Locate - find query construction: `db.Query`, `db.Exec`, `db.QueryRow`, `gormDB.Raw`, `sqlx` `NamedQuery`
- Trace data flow - identify request or form data flowing into query strings via `+`, `fmt.Sprintf`, or `strings.Join`
- Replace the unsafe pattern - convert concatenated SQL to placeholder syntax (`$1`, `?`) with values passed as separate arguments
- Bind, encode, validate, or authorize - pass every user-controlled value through `db.Query`/`db.Exec`'s variadic arguments, never through the query string
- Break taint after allowlist validation - for identifiers like a sort column, look up the user value in a `map[string]string` allowlist and use only the map's resolved value in the query, never the raw input
- Harden configuration - use a least-privilege database role for the application connection
- Test - verify with a payload such as `' OR '1'='1` against each parameterised sink, and confirm it
  is stored and compared as a literal. A stacked statement is not a useful probe: most Go drivers
  refuse multiple statements regardless of the fix, so it fails identically whether the code is
  parameterised or not
