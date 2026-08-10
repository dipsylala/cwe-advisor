# CWE-526: Exposure of Sensitive Information Through Environmental Variables

## LLM Guidance

This weakness occurs when credentials, API keys, or other secrets are stored in environment variables and then exposed through a debug endpoint, a verbose error page, logging that captures the process environment, or server-side template rendering that surfaces environment context. Environment variables are convenient for configuration but are readable by anything with process or debug access. The core fix is to stop treating environment variables as a secure store for long-lived secrets and to eliminate every code path that can surface the environment to an untrusted party.

## Key Principles

- Primary defence: fetch secrets at runtime from a dedicated secrets manager or platform secret mechanism rather than storing long-lived secrets directly as environment variables
- Remove any endpoint or debug feature that dumps the process environment; do not merely gate it behind a flag
- Never return stack traces or environment data in error responses; log full detail server-side only and return a generic message to the caller
- Sanitize logs so secret-shaped values are redacted before being written, and prefer structured logging with an explicit field allowlist over logging entire request, response, or environment objects
- Prevent server-side template injection, since a template compiled from untrusted input can be used to read environment or configuration context
- Defence-in-depth: where the platform supports it, mount secrets as files instead of environment variables, since files are not inherited by every child process or exposed through process listings

## Remediation Steps

- Locate - Identify where secrets are read from environment variables (source) and every place environment data can reach an untrusted party: debug routes, error responses, logs, template rendering (sink)
- Trace data flow - Follow the secret from its environment variable through configuration loading to where it is used or could be surfaced
- Identify the unsafe pattern - A debug or dump endpoint, verbose error handling, unfiltered logging, or template compilation of untrusted input
- Replace with the safe pattern - Retrieve secrets from a secrets manager at runtime, remove exposure paths, and return generic errors to callers
- Add secondary controls - Log redaction filters and container or orchestration secret mechanisms with restricted access
- Test - Confirm debug and error paths no longer reveal environment values, and that redaction filters catch secret-shaped log content
