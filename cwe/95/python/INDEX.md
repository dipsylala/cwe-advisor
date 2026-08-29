# CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection') - Python

## LLM Guidance

CWE-95 occurs when untrusted input from HTTP requests, APIs, files, or external sources reaches dynamic code execution: `eval()` and `exec()` run arbitrary Python with full application privileges, while `compile()` produces the code object they run and `__import__()` executes the named module's top level. The core fix is to eliminate dynamic code execution entirely and use safe alternatives like allowlisted function mappings or data deserialization.

## Key Principles

- Never use `eval()`, `exec()`, `compile()`, or `__import__()` with untrusted input; prefer `importlib.import_module` over `__import__` where a module genuinely must be named at runtime
- Replace dynamic execution with static alternatives: dictionaries, `match`/`case` statements (3.10+), or allowlists
- **`ast.literal_eval()` is not a safe parser for untrusted data, and CPython says so.** Its documentation was rewritten specifically to withdraw that claim: "This function had been documented as 'safe' in the past without defining what that meant. That was misleading... it is not free from attack: A relatively small input can lead to memory exhaustion or to C stack exhaustion, crashing the process... Calling it on untrusted data is thus not recommended." (3.9.21/3.10.8/3.11.1/3.12+.) It does prevent code execution - no namespace, no name lookups, no calls out - so it is the right tool for a trusted-but-dynamic literal, and JSON is the right tool for a request body
- `yaml.load(data, Loader=yaml.Loader)` and `yaml.UnsafeLoader` construct arbitrary Python objects; `yaml.safe_load()` is the fix, and the `Loader=` argument is the thing to check rather than the function name. Which finding you have depends on the PyYAML version: below 5.1 a bare `yaml.load(data)` silently defaulted to the unsafe loader; 5.1 to 5.4.1 warned and defaulted to `FullLoader`, which was itself RCE-capable until 5.3.1 (CVE-2020-1747) and again until **5.4** (CVE-2020-14343); from **6.0** the argument is mandatory, so a bare call raises `TypeError` and cannot be the vulnerability
- A Jinja2 `Environment` is a template engine, not a sandbox: `{{ ''.__class__.__mro__ }}`-style attribute traversal reaches module globals unless a `SandboxedEnvironment` is used. The sandbox has a bypass history, so state the floor - **3.1.6** closes the `|attr` escape (CVE-2025-27516), 3.1.5 closes the stored-`str.format` escape (CVE-2024-56326) and a compiler bug exploitable through an attacker-controlled template *filename* regardless of the sandbox (CVE-2024-56201). Even at the floor, Jinja's own guidance is that the sandbox "is not a solution for perfect security", so keep the template body out of the request
- A user-supplied `str.format` template is a related weakness rather than one this fixes: format fields perform attribute access via `getattr`, so `{0.__init__.__globals__}` reads through an argument you passed in. Route it to CWE-134 and fix it by not accepting the template
- An AST-walking evaluator is the usual replacement, and its allowlist is where it fails: permitting the attribute or subscript node types alongside names reopens the same object-graph traversal the allowlist exists to stop. Allow attribute access only where the base is one of a small hardcoded set of objects
- Apply least-privilege principles to limit damage if execution occurs

## Taint Sinks

`eval()`, `exec()`, `compile()`, `__import__()`, `yaml.load()` with an unsafe `Loader=`, `yaml.unsafe_load()`, `jinja2.Environment.from_string()`

## Remediation Steps

- Identify all uses of `eval()`, `exec()`, `compile()`, and dynamic imports in the codebase
- Replace with safe alternatives - function dictionaries, or JSON parsing for request data
- Where a literal must be parsed, use `ast.literal_eval()` only on trusted input and bound the input size; it stops code execution but not resource exhaustion
- If dynamic execution is unavoidable, implement strict input validation with character and length limits
- Run unavoidable dynamic execution in a separate locked-down process/container with minimal permissions and resource limits; do not rely on in-process Python sandboxing
- Check the manifest as well as the code - a PyYAML or Jinja2 below the floors above is the finding even where the call site looks correct
- Review and audit all external data sources feeding into the application
