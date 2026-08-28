# CWE-94: Improper Control of Generation of Code ('Code Injection') - JavaScript

## LLM Guidance

Code injection occurs when untrusted input flows into code execution functions like `eval()`, `Function()`, `setTimeout()`/`setInterval()` with strings, `vm.runInContext()`, or template engines, allowing attackers to execute arbitrary JavaScript. This grants full access to the application runtime, including file system, environment variables, and sensitive data.

## Key Principles

- Never pass user input to code evaluation functions (`eval`, `Function`, `vm` modules); Node's `vm` module is not a security boundary
- Use safe alternatives: JSON.parse() for data, allowlists for dynamic operations
- The template *body* must come from the source tree and only the substituted values may come from the request: `Handlebars.compile(req.body.templateSource)` turns attacker text into a compiled function, and auto-escaping is an XSS control that does nothing about it
- Apply principle of least privilege to execution contexts
- Validate and restrict all dynamic code paths
- `node:vm` is not a security boundary: code inside a context can reach out through `this.constructor.constructor('return process')()` and through `process.mainModule.require`, so use a separate process or a real sandbox (`isolated-vm`) where isolation is required
- Where an expression really must be evaluated, parse it and walk the AST against an allowlist of node types and operators, rejecting anything else - that leaves no call, member access, or identifier lookup for an attacker to use

- If validating by parsing, use an entry point that consumes the whole input.
  `acorn.parseExpressionAt` returns as soon as the first expression ends and silently ignores the
  rest, so a validator built on it accepts `1; require('child_process').execSync('whoami')`
- A grep for the literal token `eval(` misses the indirect forms, including `(0, eval)(code)` and a
  `Function` constructor reached through an alias

## Taint Sinks

`eval()`, `new Function()`, `setTimeout(string)`, `setInterval(string)`, `vm.runInContext()`, `vm.runInNewContext()`, `require(userInput)`, `import(userInput)`, `Handlebars.compile(userInput)`

## Remediation Steps

- Replace `eval()` with `JSON.parse()` for data parsing
- Convert `setTimeout(string)` to `setTimeout(function)` with callbacks
- Use allowlists for dynamic property access instead of bracket notation with user input
- Move any template source that is read from a request back into the source tree and pass the request data in as template values only (EJS, Pug, Handlebars)
- Gate dynamic `require()` and `import()` behind a server-side `Set` of pre-approved module names, rejecting anything else - a request-derived module name executes that module's top level
- If untrusted code execution is unavoidable, isolate it out of process or in a locked-down container with resource limits
- Apply input validation at entry points before any processing
