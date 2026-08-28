# CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - JavaScript

## LLM Guidance

SQL Injection occurs when untrusted user input is incorporated into SQL queries without proper sanitization, allowing attackers to manipulate query logic, extract data, or execute administrative operations.

**Primary Defence:** Use parameterized queries provided by Node.js database libraries (`mysql2`, `pg`, `better-sqlite3`, etc.) - prefer `mysql2` over the legacy `mysql` package, which has seen no meaningful maintenance in years.

## Key Principles

- Always use parameterized queries (prepared statements) instead of string concatenation or template literals
- Validate and sanitize user input before use, enforcing strict type checking and whitelist validation
- Apply principle of least privilege to database accounts used by the application
- Use ORMs cautiously, ensuring raw query methods still use parameterization
- Never trust client-side validation alone; always validate on the server

## Taint Sinks

`connection.query()`/`pool.query()` with a concatenated string or template literal, `sequelize.query()`, `Sequelize.literal()`, `knex.raw()`, TypeORM `dataSource.query()` and `createQueryBuilder().where()` with an interpolated condition

## Remediation Steps

- Identify all locations where user input flows into SQL queries
- Replace string concatenation and template literals with parameterized queries using placeholders (`?` or `$1`, `$2`)
- For dynamic column/table names, use strict whitelist validation rather than parameterization
- Match the binding form to the library, since no two agree: `mysql2` takes `?` with an array, `pg` takes `$1`/`$2` with an array, `knex.raw('... ?', [value])` takes an array, and TypeORM's `createQueryBuilder().where('x = :n', { n })` binds named parameters. In Sequelize, `query(sql, { bind })` uses real driver parameters while `{ replacements }` escapes and substitutes client-side - prefer `bind`; `Sequelize.literal()` and a template literal handed to `knex.raw()` bind nothing at all
- Test with SQL injection payloads to verify fixes
- Implement input validation layers before data reaches queries
