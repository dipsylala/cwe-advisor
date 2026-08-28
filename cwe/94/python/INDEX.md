# CWE-94: Improper Control of Generation of Code ('Code Injection') - Python

## LLM Guidance

Code injection in Python occurs when untrusted input is passed to code execution functions like `eval()`, `exec()`, `compile()`, or `__import__()`. This allows attackers to execute arbitrary Python code with full access to the application's runtime environment. Never use dynamic code execution with user input; use safe alternatives like literal evaluation, dictionaries for dispatch, or sandboxed parsers.

## Key Principles

- Never use `eval()`, `exec()`, or `compile()` with any user-controlled input
- Prefer JSON for external data; use `ast.literal_eval()` only with strict input size and depth limits
- Replace dynamic code execution with predefined function mappings or configuration
- Validate and sanitize all inputs before processing, using allowlists not denylists
- Jinja2 template *source* must never come from a request: `Environment.from_string()` and `render_template_string()` compile the body they are handed, and auto-escaping does not constrain it; where user-editable templates are a genuine requirement, render them through `jinja2.sandbox.SandboxedEnvironment`
- `ast.literal_eval()` is the safe evaluator for a *literal*; where an expression is genuinely needed, parse with `ast.parse(expr, mode='eval')` and walk the tree (`ast.walk`) against an allowlist of node types and operators, rejecting anything else - allowlist `ast.Expression`, `ast.Constant`, `ast.BinOp`, `ast.UnaryOp` and the `ast.operator`/`ast.unaryop` base classes, since `ast.walk` yields the operator nodes too and omitting them rejects even `1 + 2`; that leaves no name lookup, attribute access, or call for an attacker to reach. Cap the exponent or drop `ast.Pow`, because `9 ** 9 ** 9` is four allowed nodes that never return
- SymPy's `sympify()` and `parse_expr()` evaluate their input and are not safe on untrusted strings without an explicitly restricted namespace and transformations
- `importlib.import_module()` with a request-derived name executes that module's top level - map the input to a module through a fixed dictionary instead
- Route the neighbours: `pickle.loads()` is CWE-502 and a user-controlled `str.format` template is CWE-134, and neither is fixed by the AST allowlist here

## Taint Sinks

`eval()`, `exec()`, `compile()`, `__import__()`, `importlib.import_module()`, `jinja2.Environment.from_string()`, `flask.render_template_string()`

## Remediation Steps

- Replace `eval()` calls with JSON parsing where possible; if using `ast.literal_eval()`, enforce input size and nesting limits
- Convert dynamic code patterns to dictionary-based function dispatch
- Use JSON parsing instead of evaluating Python code from external sources
- Implement strict input validation with type checking and range limits
- Remove or isolate any remaining exec/eval calls to sandboxed environments
- Audit all uses of `__import__()`, `compile()`, and `importlib` for user input
