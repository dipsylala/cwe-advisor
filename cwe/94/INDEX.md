# CWE-94: Improper Control of Generation of Code ('Code Injection')

## LLM Guidance

Code injection occurs when applications dynamically generate and execute code using untrusted input, allowing attackers to inject arbitrary code that executes within the application's runtime with full access to internals, variables, functions, database connections, and secrets. Unlike command injection, which executes OS commands, code injection executes in the application's own language context. The question that separates this from its neighbours: is the attacker supplying *source text to be evaluated* (CWE-94), *a serialized object graph* (CWE-502, where the fix is a data-only format or a restricted loader), or *a format string* (CWE-134, which reads state rather than executing)? Common vulnerable patterns include eval-style dynamic code evaluation functions, embedded scripting-engine invocation, and unsafe template rendering.

## Key Principles

- Never execute dynamically generated code derived from untrusted input
- Remove eval/dynamic compilation functions or strictly sandbox with allowlists
- Use static code paths and predefined logic instead of dynamic execution
- Treat all user input as untrusted regardless of source (HTTP parameters, databases, APIs)
- Apply principle of least privilege to execution contexts
- Denylisting `eval`, `import`, `exec` or `system` in the input text is not a fix - it is bypassed by concatenation, alternate encodings, or an equivalent API the list did not anticipate; restrict what the engine can do, not what the string looks like
- A stripped-down globals or builtins namespace is not a sandbox: most dynamic languages expose introspection paths (class hierarchies, constructors, metaobjects) that reach the removed functionality without naming it
- Swapping one evaluator for another - a different script engine, a general-purpose expression library - usually keeps the capability and changes the syntax; check whether the replacement still allows type references, reflection, or method invocation
- Sinks worth searching for beyond `eval`: runtime compilation of source text, dynamic import or module loading resolved from input (which runs that module's top level), a template engine handed a user-supplied template *body*, and expression-language evaluation

## Remediation Steps

- Trace data flow from source (HTTP parameters, form inputs, file uploads, API requests, database fields) to sink - a dynamic code evaluation function or unsafe template render (see the language-specific guidance's Taint Sinks for concrete function names)
- Review scan results for specific file paths, line numbers, and variable names where code execution occurs
- Replace dynamic code execution with safer alternatives - lookup tables, predefined functions, switch statements, or configuration-driven logic
- Where dynamic execution genuinely survives, the isolation is the control: run it in a sandboxed environment with restricted access to system resources, paired with a timeout, a memory cap, and no ambient network or credentials - a sandbox without resource limits still permits denial of service and secret exfiltration
- Layer allowlist validation on top of that isolation as defence-in-depth only - a length cap, the narrowest character set the feature needs, and AST node-type allowlisting where an expression must be parsed; validation alone is insufficient and does not make an evaluator safe to keep
