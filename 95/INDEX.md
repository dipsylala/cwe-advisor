# CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')

## LLM Guidance

Eval Injection occurs when untrusted input (from HTTP requests, external APIs, databases, files, or message queues) is passed to an eval-style dynamic code evaluation function - one that compiles and executes a string as code - allowing attackers to execute arbitrary code within the application context. The core fix is to never evaluate dynamically generated code from untrusted sources - eliminate eval-style functions entirely and replace them with safe parsers or allowlisted interpreters.

## Key Principles

- Never pass untrusted data to an eval-style dynamic code evaluation function
- Replace dynamic code evaluation with safe alternatives: JSON parsers, template engines with auto-escaping, or expression evaluators with strict allowlists
- Treat all external data sources (user input, APIs, databases, files, configuration) as untrusted
- Use static analysis tools to detect and eliminate dangerous functions

## Remediation Steps

- Trace data flow: Identify where untrusted data enters (source), how it moves through the application, and where it reaches code execution functions (sink)
- Remove eval-style functions: Refactor code to eliminate dynamic code evaluation entirely (see the language-specific guidance's Taint Sinks for concrete function names)
- Use safe alternatives: Replace with a dedicated data parser (not a code evaluator) for structured data, template engines with auto-escaping for rendering, or sandboxed expression evaluators with strict syntax allowlists
- Validate and sanitize: If dynamic evaluation is unavoidable, implement strict allowlists for permitted operations and reject any input that doesn't match
- Apply defence in depth: Run code in sandboxed environments with minimal privileges and monitor for suspicious execution patterns
- Conduct security review: Use static analysis tools and manual code review to find all instances of dangerous functions
