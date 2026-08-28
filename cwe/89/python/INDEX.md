# CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Python

## LLM Guidance

SQL Injection occurs when untrusted user input is incorporated into SQL queries without proper sanitization, allowing attackers to manipulate query logic, extract data, or execute unauthorized database operations.

**Primary Defence:** Use parameterized queries provided by Python's database libraries (sqlite3, psycopg2, mysql-connector). Always use parameterized queries instead of string concatenation or f-strings when building SQL statements.

## Key Principles

- Use parameterized queries exclusively - Never concatenate user input into SQL strings
- Employ ORM frameworks - Use SQLAlchemy, Django ORM, or similar frameworks that handle parameterization
- Apply input validation - Validate data types, formats, and ranges as a secondary defence layer
- Use least privilege - Database accounts should have minimal necessary permissions
- Dynamic identifiers are allowlisted, not escaped - a table, column, or `ORDER BY` direction cannot be bound as a parameter, so validate it against a fixed set of permitted names. With psycopg2/psycopg3, build the statement from `sql.SQL()` and `sql.Identifier()`, which quotes the identifier correctly once the allowlist has chosen it

- Treat a dynamic identifier as a key into a server-side map of permitted names, not as input to
  validate and then use - the value reaching the query should be the map's, never the caller's. Ask
  first whether it needs to be caller-controlled at all: a sort parameter accepting `created_at` or
  `total` is usually a fixed set of queries wearing a dynamic costume
- Re-apply the allowlist at every endpoint consuming the same parameter; reusing the raw request value
  in a second handler is how the check gets skipped

## Taint Sinks

`cursor.execute()` with f-string/concatenation, Django `.raw()`, `.extra()`, SQLAlchemy `text()` with interpolated values

## Remediation Steps

- Replace all string concatenation and f-strings in SQL queries with parameterized placeholders
- Use the driver's placeholder syntax, and note the two named forms are not interchangeable: `sqlite3` accepts `?` and `:name`, while `psycopg2`/`psycopg3` and `mysql-connector` accept `%s` and `%(name)s` and reject `:name`. Getting this wrong raises at execution rather than falling back, so it surfaces as a broken fix rather than a silent one. `%s` here is the driver's placeholder, not Python string formatting - the values go to `cursor.execute(sql, params)` as a second argument. `cursor.execute(sql % params)` looks almost identical, interpolates the value into the SQL, and is the most common form of SQL injection in Python
- Pass user input as separate arguments to execute() methods, never embedded in query strings
- For dynamic table/column names, validate against a predefined allowlist of safe values
- Review all database interaction code for direct string manipulation
- Implement automated testing with SQL injection payloads
