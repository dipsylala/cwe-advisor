# CWE-15: External Control of System or Configuration Setting - Java

## LLM Guidance

In Java and Spring applications this occurs when request data (`@RequestParam`, `@RequestBody`, headers) is written into `System.setProperty()`, an application config map, a logger's level, or `Connection.setCatalog()`/`setSchema()`. The fix is to bind configuration once at startup with `@ConfigurationProperties` plus JSR-303 validation, and to keep configuration read-only from any HTTP-reachable code path. Where a setting must change at runtime (log level, tenant catalog, feature flag), gate it behind Spring Security authorization and an explicit allowlist.

## Key Principles

- Bind settings at startup with `@ConfigurationProperties` from `application.yml`/`application.properties`, and validate with `@Validated` plus `@Pattern`, `@Min`, `@Max`, `@NotNull`. Omitting setters does not make the binding immutable - Spring's default JavaBean binding still requires them and fails startup without one; use constructor binding (a `record`, or a class with one parameterized constructor) to actually enforce immutability
- Never call `System.setProperty()`, put arbitrary keys into an app config `Map`, or call `Connection.setCatalog()`/`setSchema()` with a value taken directly from `request.getParameter()` or a `@RequestParam`
- Treat a request-reachable `System.setProperty()` as high severity, but check which property is actually live: `http.proxyHost`/`https.proxyHost`/`http.nonProxyHosts` are read on every connection, so a runtime write redirects the next outbound request immediately. `javax.net.ssl.trustStore` and `com.sun.jndi.ldap.object.trustURLCodebase` are read once - into a static field the first time the default `SSLContext`/`TrustManagerFactory` or a JNDI LDAP lookup runs - so a write only matters if it lands before that first use, not on every request. `jdk.serialFilter` cannot be set this way at all - the JDK's own Javadoc for `ObjectInputFilter.Config` states plainly that "setting the `jdk.serialFilter` with `System.setProperty` does not set the filter"; look instead for a request-reachable call to `ObjectInputFilter.Config.setSerialFilter()` or a filter factory registration as the actual sink
- Prefer an `enum` request parameter type for admin config endpoints (e.g. `LogLevel`) so Spring MVC rejects out-of-range values with 400 before the handler runs
- Any admin endpoint that changes a setting must require `@PreAuthorize("hasRole('ADMIN')")` and check both the key and the value against a `Set<String>`/`Map<String, Set<String>>` allowlist before applying it
- Never let a request parameter select a properties file path or a remote config URL without validating the filename/hostname against an allowlist - an unvalidated URL can reach a cloud metadata endpoint (`169.254.169.254`) and a request-controlled `setConnectTimeout()`/`setReadTimeout()` of `0` blocks the calling thread indefinitely, exhausting the pool
- Log both accepted and rejected configuration changes with the acting principal for audit purposes

## Taint Sinks

`System.setProperty()`, `Connection.setCatalog()`, `Connection.setSchema()`, `Logger.setLevel()`, `Properties.load()`

## Remediation Steps

- Locate - find where `request.getParameter()`, `@RequestParam`, or a deserialized `@RequestBody` flows into `System.setProperty()`, a config `Map.put()`, `Logger.setLevel()`, `Connection.setCatalog()`, or `Properties.load()`/`FileInputStream` with a path argument
- Trace data flow - follow the value from the controller method parameter to the configuration or system call that consumes it, including any DTO fields it is copied through
- Replace the unsafe pattern - move the setting into a `@ConfigurationProperties`-bound class populated from `application.yml` or environment variables set at deployment, not from the request
- Bind, encode, validate, or authorize - if the value must stay runtime-configurable, require `@PreAuthorize("hasRole('ADMIN')")` and validate the key/value pair against a `Map<String, Set<String>>` of permitted settings
- Break taint after allowlist validation - assign the matched allowlist entry to a fresh local variable before calling `Logger.setLevel()`, `Connection.setCatalog()`, or the config service, never the raw request value; with Logback, reach the root logger via `(LoggerContext) LoggerFactory.getILoggerFactory()` and `getLogger("ROOT").setLevel(Level.valueOf(...))`
- Harden configuration - enable Spring's `@Validated` on the configuration class so invalid startup configuration fails the application context instead of degrading security silently
- Test - submit values outside the allowlist and confirm 400, confirm unauthenticated calls to admin config endpoints return 401/403, and confirm the app context fails to start with invalid `application.yml` values
