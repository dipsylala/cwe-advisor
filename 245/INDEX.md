# CWE-245: J2EE Bad Practices: Direct Management of Connections

## LLM Guidance

This weakness appears in J2EE/Jakarta EE applications when code obtains a resource such as a database connection directly (bypassing the container's connection-management facilities) instead of through a container-managed, pooled resource. Direct management creates an unpooled connection per call, often forces credentials into application code or config files, and leaves lifecycle and cleanup entirely to the developer instead of the platform built to handle it. The remediation is to obtain connections exclusively from a container- or framework-managed, pooled resource and to guarantee cleanup on every exit path, including exceptions.

## Key Principles

- Primary defence: obtain connections from a container-managed, pooled resource rather than creating them directly in application code.
- Never construct a connection with inline credentials; externalize credentials to container-managed configuration, environment variables, or a secrets manager.
- Guarantee that every acquired connection is released on every exit path, including exceptions, rather than relying on a developer-written cleanup block that can be skipped.
- Configure the connection pool with an explicit maximum size and leak detection; an unbounded or unmonitored pool can still be exhausted under load.
- Do not manage transaction state manually on a pooled connection; let the container or framework manage transaction boundaries so connection state is left correct for whichever request reuses it next.
- Defence-in-depth: audit for direct connection-management calls as part of code review, since the pattern degrades reliability and availability even when it does not directly cause a data breach.

## Remediation Steps

- Locate - Search for direct connection-creation calls in application code, and for connection strings with embedded credentials in code or checked-in configuration.
- Trace data flow - Identify every code path that acquires a connection this way and every exit path (including exceptions) that must release it.
- Identify the unsafe pattern - Confirm the connection is created directly rather than obtained from a container- or framework-managed pooled resource, and confirm whether cleanup is guaranteed on all exit paths.
- Replace with the safe pattern - Obtain connections from a pooled, container- or framework-managed resource, and use a resource-scoped construct that guarantees release even on exceptions.
- Add secondary controls - Configure an explicit pool size limit and enable leak detection; externalize credentials outside source and checked-in configuration.
- Test - Load-test the affected code path and confirm the number of active connections stays bounded at the configured pool size rather than growing with request volume; confirm no credentials remain in source, compiled artifacts, or checked-in configuration.
