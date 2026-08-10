# CWE-943: Improper Neutralization of Special Elements in Data Query Logic

## LLM Guidance

This weakness covers query injection into non-relational or structure-based query languages, such as NoSQL document databases, LDAP directories, and ORM/ODM query builders that accept raw operators or filter objects. It occurs when untrusted input is allowed to influence query structure, not just query values, so request data can inject operators, alter filter logic, or trigger server-side code execution. The core fix is to constrain untrusted input to plain scalar values bound through the driver's parameterized or strongly-typed query API, and to reject any input shaped like a query operator or object where a scalar is expected.

## Key Principles

- Never pass raw, unvalidated request data (JSON bodies, dictionaries, maps) directly as or into a query filter object
- Use the database driver's or ORM/ODM's structured, parameterized query API as the primary defence, not string concatenation or dictionary merging
- Enforce a strict type check (string, number, boolean) on every field before it reaches the query builder; reject objects or arrays where a scalar is expected
- Allowlist which fields a query may filter, sort, or project on, and reject any input key that begins with a query-operator prefix
- Never enable server-side expression or code-execution features of the query engine with any part of the expression derived from user input
- Apply least privilege to the database account used by the application

## Remediation Steps

- Locate - Identify the untrusted source (request parameters, JSON body, headers) and the sink (the query-building call, filter object, or raw query string)
- Trace data flow - Follow the value from input parsing through any merging, spreading, or reassignment into a query object, filter, or aggregation pipeline
- Identify the unsafe pattern - Look for user input passed directly as a query object, raw JSON accepted as a filter, or string concatenation building a query
- Replace with the safe pattern - Convert to the driver's structured, parameterized query API, binding each value explicitly rather than accepting a caller-supplied object
- Break taint after allowlist validation - Once a field name or operator is checked against an allowlist, use the allowlisted value for the query, not the original input
- Add secondary controls - Enforce strict per-field type validation, reject operator-shaped keys, and scope the database account to least privilege
- Test - Verify the fix using operator-injection payloads (a comparison operator in place of a scalar value) and type-confusion payloads (an object submitted where a string is expected)
