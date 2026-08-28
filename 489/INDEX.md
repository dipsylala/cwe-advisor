# CWE-489: Active Debug Code

## LLM Guidance

Leftover debug code in production (print statements, test backdoors, disabled authentication, verbose error messages, debug endpoints) exposes sensitive information, creates security bypasses, and provides attackers with reconnaissance data. Core principle: Remove or strictly gate all debug paths before production deployment.

## Key Principles

- Remove before shipping: Strip debug code, test accounts, and development features from production builds
- Gate debug features: If debug functionality is needed, protect it behind authentication, authorization, and environment checks
- Disable by default: Ensure DEBUG flags, verbose logging, and development modes are off in production configurations
- Sanitize error output: Replace detailed error messages with generic responses; log details server-side only
- Use build-time removal: Configure build tools to automatically strip debug code from production artifacts
- The weakness is that a development-only path is *reachable*, whether or not it discloses anything: a test account, a header that grants a session, a `?debug=true` branch, or a registered `/debug` route is this finding even when it leaks nothing, because the functionality is the exposure and deleting it is the fix
- Use this entry when the fix is removing an affordance, and the disclosure entries when the fix is changing what a still-wanted output contains: what debug instrumentation puts in its output is CWE-215, system and environment detail is CWE-497, an error message as the vehicle is CWE-209, and a log file as the destination is CWE-532
- Older tooling calls this "Leftover Debug Code", the name it carried until 2020

## Remediation Steps

- Search for debug patterns - Find print/console statements, debug flags, test credentials, and debug endpoints (e.g., `/debug/*`, `/test/*`)
- Review configurations - Check for `DEBUG=true`, development settings, and verbose logging enabled in production config files
- Remove test backdoors - Eliminate test accounts, authentication bypasses, and `?debug=true` parameters
- Sanitize error handlers - Replace stack traces and verbose errors exposed to users with generic messages
- Examine data flows - Review scan data_paths to locate where debug code exists in production paths
- Implement environment checks - Wrap any necessary debug features with strict environment validation and access controls
