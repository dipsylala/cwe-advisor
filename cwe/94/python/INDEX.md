# CWE-94: Improper Control of Generation of Code ('Code Injection') - Python

## LLM Guidance

Code injection in Python occurs when untrusted input is passed to code execution functions like `eval()`, `exec()`, `compile()`, or `__import__()`. This allows attackers to execute arbitrary Python code with full access to the application's runtime environment. Never use dynamic code execution with user input; use safe alternatives like literal evaluation, dictionaries for dispatch, or sandboxed parsers.

## Key Principles

- Never use `eval()`, `exec()`, or `compile()` with any user-controlled input
- Prefer JSON for external data; use `ast.literal_eval()` only with strict input size and depth limits
- Replace dynamic code execution with predefined function mappings or configuration
- Validate and sanitize all inputs before processing, using allowlists not denylists
- Jinja2 template *source* must never come from a request: `Environment.from_string()` and `render_template_string()` compile the body they are handed, and auto-escaping does not constrain it; where user-editable templates are a genuine requirement, render them through `jinja2.sandbox.SandboxedEnvironment`, which Jinja does support for untrusted templates but only with the preconditions it states: run under CPU and memory limits, since a small template can render to very large output, and pass only the data the template needs rather than globals or objects whose methods have side effects
- `ast.literal_eval()` is the right evaluator for a *literal*, but not an unqualified safe one: its
  own documentation withdraws the word, noting it was "documented as 'safe' in the past without
  defining what that meant" and that "calling it on untrusted data is thus not recommended", because
  a small input can exhaust memory or the C stack. Cap the input's length and nesting before the call
  rather than treating the function as the boundary; where an expression is genuinely needed, parse with `ast.parse(expr, mode='eval')` and walk the tree (`ast.walk`) against an allowlist of node types and operators, rejecting anything else - allowlist `ast.Expression`, `ast.Constant`, `ast.BinOp`, `ast.UnaryOp` and the `ast.operator`/`ast.unaryop` base classes, since `ast.walk` yields the operator nodes too and omitting them rejects even `1 + 2`; that leaves no name lookup, attribute access, or call for an attacker to reach. Where the formula must reference variables (`price * qty`), add `ast.Name` *and* `ast.Load` - `ast.walk` yields the `Load` context node hanging off every `Name`, so an allowlist with `Name` but not `Load` rejects every variable reference and the endpoint stops working for all legitimate formulas - and check each `Name.id` against the set of variables the caller supplies, never against `globals()`. Cap the exponent or drop `ast.Pow`, because `9 ** 9 ** 9` is four allowed nodes that never return
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
- Remove any remaining `exec`/`eval` on untrusted input rather than trying to contain it. CPython has
  no sandbox for these and says so: overriding `__builtins__` "is *not* a security mechanism: the
  executed code can still access all builtins". Where isolation is genuinely required it has to come
  from outside the interpreter - a separate process with OS-level limits
- Audit all uses of `__import__()`, `compile()`, and `importlib` for user input
