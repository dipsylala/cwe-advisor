# CWE-382: J2EE Bad Practices: Use of System.exit() - Java

## LLM Guidance

Calling `System.exit()` inside a servlet, filter, listener, or EJB business method terminates the entire JVM hosting the application server, not just the current request - a single validation failure or handled exception can take down every deployed application and every connected user. The fix is always to replace `System.exit()` with an exception (`ServletException`, an application-specific exception, or `response.sendError()`) so the container's own request/thread lifecycle absorbs the failure. Reserve `System.exit()` exclusively for the application's designated top-level entrypoint (a standalone `main()` in a CLI tool), never for library, shared, or container-managed code paths.

## Key Principles

- Never call `System.exit()` from a servlet, filter, listener, or EJB business method - it terminates the whole JVM, not just the current request
- Replace error/validation failures with a thrown exception (`ServletException`, a custom application exception) or `response.sendError()` so the container handles the failure per-request
- In EJBs, throw application exceptions so the container manages transaction rollback without destroying the bean instance
- For initialization failures (`init()`, constructors), throw `ServletException` instead of exiting - this marks only that component unavailable rather than preventing the whole server from starting
- For shutdown-path failures (`destroy()`, `@PreDestroy`), log the error and let the container continue its own shutdown sequence rather than forcing a harder exit
- Do not rely on a `SecurityManager` to block `System.exit()` as the primary control - `SecurityManager` has been deprecated for removal since JDK 17 (JEP 411) and is permanently disabled as of JDK 24 (JEP 486), so a `checkExit()` override no longer runs at all on current JDKs; the fix is removing the call, not sandboxing it

## Taint Sinks

`System.exit()`, `Runtime.getRuntime().exit()`, `Runtime.getRuntime().halt()`

## Remediation Steps

- Locate - Search for `System.exit(` in servlets, filters, listeners, and EJBs using grep or IDE search across the web and EJB tiers
- Trace data flow - Determine the triggering condition (DB failure, validation failure, auth failure, startup failure, shutdown failure) to pick the right replacement
- Replace the unsafe pattern - Convert request-path calls to `throw new ServletException("message", cause)` or `response.sendError(HttpServletResponse.SC_*, "message")`
- Bind, encode, validate, or authorize - In EJBs, throw an application exception (not `System.exit()`) so the container rolls back the transaction and returns the bean to the pool
- Harden configuration - For repeated external-dependency failures that motivated the exit call, add a circuit breaker (e.g. Resilience4j) instead of terminating the process
- Test - Trigger each error path (bad input, failed DB connection, failed auth, missing config, shutdown failure) and confirm the server stays up and continues serving other requests
