# CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - C#

## LLM Guidance

SQL Injection occurs when untrusted data is incorporated into SQL queries without proper validation or parameterization, allowing attackers to manipulate queries to bypass authentication, access unauthorized data, modify/delete records, or execute administrative operations.

**Primary Defence:** Use parameterized queries with `SqlCommand.Parameters`, Entity Framework LINQ queries, or Dapper with parameter binding.

## Key Principles

- Always use parameterized queries; never concatenate user input into SQL strings
- Prefer Entity Framework LINQ queries which automatically parameterize
- Use stored procedures with parameters when direct SQL is unavoidable
- Validate and sanitize all user input at entry points
- Apply least privilege to database accounts

- Treat a dynamic identifier as a key into a server-side map of permitted names, not as input to
  validate and then use - the value reaching the query should be the map's, never the caller's. Ask
  first whether it needs to be caller-controlled at all: a sort parameter accepting `created_at` or
  `total` is usually a fixed set of queries wearing a dynamic costume
- Re-apply the allowlist at every endpoint consuming the same parameter; reusing the raw request value
  in a second handler is how the check gets skipped

## Taint Sinks

`SqlCommand.ExecuteReader()`, `SqlCommand.ExecuteNonQuery()`, `SqlCommand.ExecuteScalar()`, `FromSqlRaw()`, `ExecuteSqlRaw()`, `SqlDataAdapter.Fill()`

## Remediation Steps

- Review data flow from source (Request.QueryString, Request.Form, route parameters) to sink (ExecuteReader, FromSqlRaw, ExecuteSqlRaw)
- Identify string concatenation or interpolation in SQL query construction
- Replace concatenated queries with parameterized alternatives, declaring an explicit type: `Parameters.Add` returns the new parameter without a value, so assign it on the returned object - `cmd.Parameters.Add("@id", SqlDbType.Int).Value = id;`. A parameter left unassigned fails at execute time rather than at compile time. Pass the optional `size` argument only for variable-length types such as `SqlDbType.VarChar` and `SqlDbType.NVarChar`, where a size set smaller than the value truncates it rather than raising; for fixed-width types the value is ignored. Prefer `Parameters.Add` with an explicit `SqlDbType` over `AddWithValue()`, which infers the type from the runtime value - but treat that as a typing and plan-stability preference rather than part of this finding, since `AddWithValue` parameterises just as completely and Microsoft's own reference recommends it for convenience
- For Entity Framework Core the parameterising methods are `FromSql` (EF Core 7.0 and later) and
  `FromSqlInterpolated` (the name to use before that); both wrap each interpolated value in a
  `DbParameter` rather than concatenating it. `ExecuteSql`/`ExecuteSqlRaw` are the non-query
  equivalents and `SqlQuery`/`SqlQueryRaw` the scalar ones. `FromSqlRaw` is not automatically the
  defect - EF Core documents it as safe when the values are passed as `DbParameter` arguments, so
  check how the arguments reach it before rewriting the call
- A dynamic table, column or `ORDER BY` name cannot be fixed this way, and this is where the obvious
  rewrite fails: no database allows parameterising a column name or any other part of the schema, so
  `FromSql`/`FromSqlInterpolated` on an identifier does not work at all. EF Core's own guidance is to
  use `FromSqlRaw` there and make the identifier safe by construction - resolve the user's value
  against an application-controlled allowlist of permitted column names and interpolate the matched
  constant, keeping the row values as parameters
- Verify all user-supplied values are passed as parameters, not embedded in query strings
- Test the fix to ensure functionality and confirm scan results are resolved
