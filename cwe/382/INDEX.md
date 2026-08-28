# CWE-382: J2EE Bad Practices: Use of System.exit()

## LLM Guidance

Calling System.exit() in J2EE applications terminates the entire application server, affecting all deployed applications and users. This violates the J2EE threading model, prevents proper cleanup of container-managed resources, and causes denial of service.

## Key Principles

- Never expose dangerous functionality like System.exit() in untrusted J2EE contexts
- Use exception-based error handling instead of process termination
- Rely on container-managed lifecycle for application shutdown
- Keep privileged operations gated and isolated from application code
- Allow the J2EE container to manage resource cleanup and thread lifecycle
- Look for the calls that do not read as an exit: `System.exit()` delegates to `Runtime.getRuntime().exit()`, and `Runtime.halt()` skips shutdown hooks entirely, so a grep for `System.exit` alone misses both
- Replace the exit with a failure the container understands - a `ServletException` for a request-scoped failure, an application exception (`@ApplicationException`) in an EJB so the transaction is handled rather than the process, or `response.sendError()` for a client error
- Do cleanup in the container's own hooks (`contextDestroyed`, `@PreDestroy`) rather than in the code path that wanted to exit
- Severity follows how shared the process is: a multi-tenant application server takes every co-deployed application down with it, while a fat JAR running one application behind a restarting supervisor has a smaller blast radius - a validation failure that terminates the process is still a denial of service any client can trigger

## Remediation Steps

- Locate calls - Search for `System.exit` in servlets, EJBs, filters, and JSPs using grep or IDE search
- Identify context - Determine why System.exit() is called (error handling, validation failure, shutdown logic)
- Replace with exceptions - Use `throw new ServletException("message")` or appropriate exception types instead of System.exit()
- Use container shutdown - If legitimate shutdown needed, use container management tools or JMX beans
- Implement proper error handling - Return error responses, log failures, and set HTTP status codes appropriately
- Verify fix - Test error paths to confirm server remains operational after handled failures
