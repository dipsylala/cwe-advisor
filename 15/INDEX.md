# CWE-15: External Control of System or Configuration Setting

## LLM Guidance

This vulnerability occurs when user input controls system or application configuration settings, allowing attackers to alter application behavior, security controls, or environment variables. The core fix is to never allow untrusted input to directly control configuration - all settings must be defined and enforced by trusted code. Where the externally-controlled state is broader than configuration (session, workflow, or other critical state), use CWE-642 instead.

## Key Principles

- Define all configuration through trusted deployment mechanisms, not runtime user input
- Use allowlists to constrain configuration values to known-safe options
- Never accept configuration key names from user input; map a user's choice to an internal key
- Separate user preferences from security-critical system configuration
- Require authentication and admin-level authorization on any endpoint that changes configuration, and audit every change
- Treat the configuration *source* as a sink too - a file path, URL, uploaded file, or user-writable database row that the application reads its config from is externally controlled configuration
- Validate and sanitize any user data that influences application behavior
- Enforce configuration integrity through code-based defaults

## Remediation Steps

- Review scan results for file path, line number, and variables where user input controls configuration
- Trace data flow from untrusted sources (HTTP params, headers, cookies) to configuration sinks such as `config.set()`, `os.environ[key] = value`, or `System.setProperty()`
- Replace direct user input with predefined configuration options selected via allowlist, validating type and range for numeric settings
- Move security-sensitive settings to deployment configuration files or environment variables, and treat configuration as immutable after startup where runtime changes are not a product requirement
- Enforce admin-only authorization on any surviving configuration endpoint and log who changed which setting to what value
- Check how configuration is loaded, not just how it is assigned - hardcode or allowlist the directory for config file paths (path traversal), hardcode internal config endpoints rather than fetching a user-supplied URL (SSRF, CWE-918), parse uploaded config with safe parsers (`yaml.safe_load()`, external entity processing disabled - CWE-502, CWE-611), and re-validate database-sourced config on read
- Implement validation layers that reject unexpected configuration values and fail back to the previous secure value
- Conduct code review to identify additional instances of externally-controlled settings
