# CWE-15: External Control of System or Configuration Setting - C#

## LLM Guidance

In .NET applications this occurs when request data (query strings, form fields, headers, route values) is written into `IConfiguration`, `Environment.SetEnvironmentVariable()`, `ConfigurationManager.AppSettings`, logging minimum levels, or connection/catalog selection at runtime. The fix is to bind configuration once at startup with `IOptions<T>` and DataAnnotations validation, and to keep configuration read-only from any HTTP-reachable code path. Where a setting must be changeable at runtime (log level, feature flag, tenant catalog), gate it behind admin authorization and an explicit allowlist.

## Key Principles

- Bind settings at startup with `IOptions<T>` (or `IOptionsSnapshot<T>`/`IOptionsMonitor<T>` for reload-from-file scenarios) rather than reading request data into configuration objects
- Never cast `IConfiguration` to `IConfigurationRoot` to write values, and never call `Environment.SetEnvironmentVariable()` or `ConfigurationManager.AppSettings.Set()` with request-derived keys or values
- Validate bound settings with DataAnnotations (`[Required]`, `[Range]`, `[RegularExpression]`) plus `ValidateOnStart()` so invalid configuration fails at boot, not silently at runtime
- Use Serilog's `LoggingLevelSwitch` for any legitimate runtime log-level control instead of rebuilding the logger from a request value
- Any admin endpoint that changes a setting must authorize with `[Authorize(Roles = "Admin")]` and check the requested key and value against a `HashSet<string>` allowlist before applying it
- Never let a request parameter select a database catalog (`SqlConnection.ChangeDatabase()`), a config file path, or a remote config URL without allowlist validation

## Taint Sinks

`Environment.SetEnvironmentVariable()`, `ConfigurationManager.AppSettings.Set()`, `IConfigurationRoot` indexer set, `SqlConnection.ChangeDatabase()`

## Remediation Steps

- Locate - find where `Request`, route values, or deserialized request bodies flow into `IConfiguration` indexers, `Environment.SetEnvironmentVariable()`, `ConfigurationManager.AppSettings`, logger level setters, `ChangeDatabase()`, or file/URL loading calls
- Trace data flow - follow the value from controller action parameter or `[FromBody]`/`[FromQuery]` model through to the configuration or system call that consumes it
- Replace the unsafe pattern - move the setting into an `AppSettings` class bound via `AddOptions<T>().Bind(...)` from `appsettings.json` or environment variables set at deployment, not from the request
- Bind, encode, validate, or authorize - if the value must remain runtime-configurable, require `[Authorize(Roles = "Admin")]` and validate the key against a `Dictionary<string, HashSet<string>>` of permitted keys and values
- Break taint after allowlist validation - assign the matched allowlist entry to a fresh local variable and pass that variable to `LoggingLevelSwitch.MinimumLevel`, `ChangeDatabase()`, or the config service, never the raw request value
- Harden configuration - enable `ValidateDataAnnotations().ValidateOnStart()` so misconfiguration fails startup instead of degrading security silently
- Test - submit values outside the allowlist and confirm 400, confirm unauthenticated requests to admin config endpoints return 401/403, and confirm the app refuses to start with an invalid `appsettings.json`

## Safe Pattern

```csharp
// SAFE: startup-bound, validated configuration - no request can reach it
public class AppSettings
{
    [RegularExpression("^(Information|Warning|Error)$")]
    public string LogLevel { get; init; } = "Information";
}

builder.Services.AddOptions<AppSettings>()
    .Bind(builder.Configuration.GetSection("App"))
    .ValidateDataAnnotations()
    .ValidateOnStart();

// SAFE: runtime log-level change gated by auth + allowlist
private static readonly HashSet<string> AllowedLogLevels =
    new(StringComparer.OrdinalIgnoreCase) { "Information", "Warning", "Error" };

[HttpPost("admin/log-level")]
[Authorize(Roles = "Admin")]
public IActionResult SetLogLevel([FromBody] LogLevelRequest request)
{
    if (!AllowedLogLevels.Contains(request.Level))
        return BadRequest("Invalid level");

    // Allowlist-selected value is what reaches the sink, not request.Level directly
    var approvedLevel = Enum.Parse<LogEventLevel>(request.Level, ignoreCase: true);
    _levelSwitch.MinimumLevel = approvedLevel;
    return Ok();
}
```
