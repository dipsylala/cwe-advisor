# CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection') - Python

## LLM Guidance

CWE-95 occurs when untrusted input from HTTP requests, APIs, files, or external sources is passed to dynamic code execution functions like `eval()`, `exec()`, `compile()`, or `__import__()`. These functions execute arbitrary Python code with full application privileges, enabling attackers to access data, modify system state, or execute commands. The core fix is to eliminate dynamic code execution entirely and use safe alternatives like whitelisted function mappings, AST parsing, or data serialization.

## Key Principles

- Never use `eval()`, `exec()`, `compile()`, or `__import__()` with untrusted input
- Replace dynamic execution with static alternatives: dictionaries, match/case statements, or allowlists
- Use safe parsers like `ast.literal_eval()` for data structures or JSON for configuration
- Validate and sanitize all input with strict whitelists before any processing
- Apply least-privilege principles to limit damage if execution occurs
- `yaml.load(data, Loader=yaml.Loader)` and `yaml.UnsafeLoader` construct arbitrary Python objects; `yaml.safe_load()` is the fix, and the `Loader=` argument is the thing to check rather than the function name
- A Jinja2 `Environment` is a template engine, not a sandbox: `{{ ''.__class__.__mro__ }}`-style attribute traversal reaches module globals unless a `SandboxedEnvironment` is used, and even then the template body must not come from a request
- `str.format` on a user-supplied template is a different weakness (CWE-134) and is not fixed by anything here

## Taint Sinks

`eval()`, `exec()`, `compile()`, `__import__()`

## Remediation Steps

- Identify all uses of `eval()`, `exec()`, `compile()`, and dynamic imports in the codebase
- Replace with safe alternatives - function dictionaries, `ast.literal_eval()`, or JSON parsing
- If dynamic execution is unavoidable, implement strict input validation with character and length limits
- Run unavoidable dynamic execution in a separate locked-down process/container with minimal permissions and resource limits; do not rely on in-process Python sandboxing
- Apply input whitelisting to allow only specific, predefined values or patterns
- Review and audit all external data sources feeding into the application
