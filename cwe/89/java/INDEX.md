# CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Java

## LLM Guidance

SQL Injection occurs when untrusted data is incorporated into SQL queries without proper validation or parameterization, allowing attackers to manipulate queries to bypass authentication, access unauthorized data, or modify records. Use `PreparedStatement` with parameterized queries, JPA/Hibernate named parameters, or query builder frameworks that automatically parameterize values.

## Key Principles

- Always use parameterized queries or prepared statements - never concatenate user input into SQL strings
- Prefer ORM frameworks (JPA/Hibernate) with bound parameters over raw JDBC
- In MyBatis, use `#{}` for bound parameters; it generates a `PreparedStatement` placeholder. `${}`
  performs raw text substitution and is as unsafe as string concatenation for a *value* - but it is
  also MyBatis's documented mechanism for a dynamic table or column name, which `#{}` cannot express.
  So a `${}` on an identifier is not removed, it is made safe by construction: resolve the input
  against an allowlist and substitute the matched constant
- `PreparedStatement` is not safe by virtue of its type: `prepareStatement("... WHERE name='" + name + "'")` is already injected before the statement is prepared. The protection comes from `?` placeholders plus `setString()`/`setInt()`, so judge the fix by what the SQL string was built from, not by which class executes it
- Validate and sanitize input as a secondary defence layer
- Apply least privilege principles to database accounts
- Use stored procedures with parameterized inputs where appropriate

- Treat a dynamic identifier as a key into a server-side map of permitted names, not as input to
  validate and then use - the value reaching the query should be the map's, never the caller's. Ask
  first whether it needs to be caller-controlled at all: a sort parameter accepting `created_at` or
  `total` is usually a fixed set of queries wearing a dynamic costume
- Re-apply the allowlist at every endpoint consuming the same parameter; reusing the raw request value
  in a second handler is how the check gets skipped

## Taint Sinks

`Statement.executeQuery()`, `Statement.executeUpdate()`, `createNativeQuery()`, `EntityManager.createQuery()` (JPQL injects the same way), Spring `JdbcTemplate.query()`/`queryForObject()` given a built string, MyBatis `${}` substitution

## Remediation Steps

- Locate - Identify the source (user input entry points like `request.getParameter()`, `@RequestParam`) and sink (SQL execution like `executeQuery()`, `createNativeQuery()`)
- Trace data flow - Check if string concatenation or `String.format()` is used to build SQL queries
- Replace concatenation - Convert string-based queries to `PreparedStatement` with `?` placeholders or
  JPA named parameters (`:paramName`). Both are restricted to value positions - the Jakarta
  Persistence specification allows input parameters only in a `WHERE` or `HAVING` clause - so a sort
  column, entity name or attribute path still has to come from an allowlist, and that is usually the
  half of a JPQL query that was concatenated in the first place
- Bind parameters - Use `setString()`, `setInt()` or similar methods to bind user input to placeholders
- Test - Verify the fix handles special characters and injection attempts correctly
- Review - Ensure all similar patterns in the codebase are addressed
