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

## Taint Sinks

`SqlCommand.ExecuteReader()`, `SqlCommand.ExecuteNonQuery()`, `SqlCommand.ExecuteScalar()`, `FromSqlRaw()`, `ExecuteSqlRaw()`, `SqlDataAdapter.Fill()`

## Remediation Steps

- Review data flow from source (Request.QueryString, Request.Form, route parameters) to sink (ExecuteReader, FromSqlRaw, ExecuteSqlRaw)
- Identify string concatenation or interpolation in SQL query construction
- Replace concatenated queries with parameterized alternatives, declaring an explicit type: `Parameters.Add` returns the new parameter without a value, so assign it on the returned object - `cmd.Parameters.Add("@id", SqlDbType.Int).Value = id;`. A parameter left unassigned fails at execute time rather than at compile time. Pass the optional `size` argument only for variable-length types such as `SqlDbType.VarChar` and `SqlDbType.NVarChar`; it has no meaning for fixed-width types. Avoid `AddWithValue()`, which lets ADO.NET infer the SQL type and can cause query-plan cache bloat and implicit truncation/type-mismatch bugs
- For Entity Framework, replace `FromSqlRaw` with `FromSqlInterpolated` or LINQ queries
- Verify all user-supplied values are passed as parameters, not embedded in query strings
- Test the fix to ensure functionality and confirm scan results are resolved
