# CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

## LLM Guidance

SQL Injection occurs when untrusted data is incorporated into SQL queries without proper sanitization, allowing attackers to manipulate query logic, access unauthorized data, or execute administrative operations. The core fix is to use parameterized queries (prepared statements) so user input is always treated as data, not query structure. For NoSQL or document-store query injection (operator injection, filter object manipulation), use CWE-943 instead.

## Key Principles

- Never build SQL by concatenating untrusted input directly into queries
- Use parameterized queries/prepared statements as the primary defence
- Treat all user input as untrusted data, not executable SQL code
- Apply defence-in-depth: combine parameterized queries with input validation and least privilege
- Avoid dynamic query construction; use static SQL with parameters
- Placeholders stand in for values, not for structure: a table name, column name, or `ORDER BY` direction cannot be bound, so those positions need allowlist validation against a fixed set of permitted identifiers
- Manual escaping is not an equivalent fix - doubling quotes or calling a driver escape function does nothing for an unquoted numeric context (`id = 1 OR 1=1`) and is applied inconsistently across a codebase
- Watch for second-order injection: a value stored safely and later read back is still untrusted when it is concatenated into a different query
- Grant the application account only the privileges it needs rather than revoking dangerous ones - a fresh account holds nothing to revoke, and a revoke list can only name the privileges its author thought of

## Remediation Steps

- Trace the data path - Identify the source (user input, external data) and sink (SQL execution function like `.execute()`, `.query()`)
- Locate string concatenation - Find instances of `+`, `concat()`, `format()`, or template literals building SQL with untrusted data
- Replace with parameterized queries - Convert concatenated SQL to prepared statements with placeholders (`?`, `$1`, `:param`)
- Bind parameters separately - Pass untrusted data as separate parameters to the query execution function
- Validate input - Add input validation as a secondary defence layer (allowlist permitted values, validate types/formats); it never substitutes for parameterization, and blocklisting keywords such as `SELECT`, `DROP`, or `--` is defeated by case variation and inline comments while rejecting legitimate data
- Test thoroughly - Verify the fix prevents injection by testing with malicious payloads (e.g., `' OR '1'='1`)
