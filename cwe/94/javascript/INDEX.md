# CWE-94: Improper Control of Generation of Code ('Code Injection') - JavaScript

## LLM Guidance

Code injection occurs when untrusted input flows into code execution functions like `eval()`, `Function()`, `setTimeout()`/`setInterval()` with strings, `vm.runInContext()`, or template engines, allowing attackers to execute arbitrary JavaScript. This grants full access to the application runtime, including file system, environment variables, and sensitive data.

## Key Principles

- Never pass user input to code evaluation functions (`eval`, `Function`, `vm` modules); Node's `vm` module is not a security boundary
- Use safe alternatives: JSON.parse() for data, allowlists for dynamic operations
- The template *body* must come from the source tree and only the substituted values may come from the request: `Handlebars.compile(req.body.templateSource)` turns attacker text into a compiled function, and auto-escaping is an XSS control that does nothing about it
- Apply principle of least privilege to execution contexts
- Validate and restrict all dynamic code paths
- `node:vm` is not a security boundary: code inside a context can reach out through `this.constructor.constructor('return process')()` and through `process.mainModule.require`, so where isolation is required the boundary is a separate process - optionally running `isolated-vm` inside it, which its own README asks for ("a good idea to keep instances of `isolated-vm` in a different nodejs process") while stating the library is in maintenance mode and does not make an application safe by itself. In `isolated-vm` a host function does not cross into the isolate as a function: a `Reference` arrives as an object that the sandboxed code must call through `applySync()`, so a script written as `emit(id, action)` throws "emit is not a function" - pass `new ivm.Callback(fn)`, which becomes a plain function on the other side, or rewrite the sandboxed call sites. Prefer `Callback` for the same reason: a `Reference` handed into the isolate exposes its target's prototype chain, which is the documented escape route (CVE-2021-21413)
- Where an expression really must be evaluated, parse it and walk the AST against an allowlist of node types and operators, rejecting anything else - that leaves no call, member access, or identifier lookup for an attacker to use. An expression library is not that check by itself. `expr-eval` is the one models reach for, and it needs two qualifications: the original package stopped at 2.0.2 in 2019 and carries CERT VU#263614 (CVE-2025-12735, arbitrary code execution through an attacker-influenced variables object, plus prototype pollution) with no fixed release - the maintained line is `expr-eval-fork`, where the floor is 3.0.1: 3.0.0 is still inside the CVE-2025-12735 range and the prototype-pollution half (CVE-2025-13204) was fixed at 2.0.2; and even there, pass only primitive values in the variables object and keep the expression length and operator set bounded. Its export shape, for the import: `Parser` (`Parser.evaluate(expr, vars)` or `new Parser().parse(expr).evaluate(vars)`), with no top-level `evaluate`, so destructuring one yields `undefined` and every call throws

- If validating by parsing, use an entry point that consumes the whole input.
  `acorn.parseExpressionAt` returns as soon as the first expression ends and silently ignores the
  rest, so a validator built on it accepts `1; require('child_process').execSync('whoami')`
- A grep for the literal token `eval(` misses the indirect forms, including `(0, eval)(code)` and a
  `Function` constructor reached through an alias

## Taint Sinks

`eval()`, `new Function()`, `setTimeout(string)`/`setInterval(string)` in a browser - on Node both throw `ERR_INVALID_ARG_TYPE` before anything runs, so a server-side finding there is a crash rather than an injection - `vm.runInContext()`, `vm.runInNewContext()`, `require(userInput)`, `import(userInput)`, `Handlebars.compile(userInput)`

## Remediation Steps

- Replace `eval()` with `JSON.parse()` for data parsing
- Convert a browser's `setTimeout(string)` to `setTimeout(function)` with callbacks; on Node the string form already throws, so the same change there fixes a runtime error rather than an injection
- Use allowlists for dynamic property access instead of bracket notation with user input
- Move any template source that is read from a request back into the source tree and pass the request data in as template values only (EJS, Pug, Handlebars)
- Gate dynamic `require()` and `import()` behind a server-side `Set` of pre-approved module names, rejecting anything else - a request-derived module name executes that module's top level
- If untrusted code execution is unavoidable, isolate it out of process or in a locked-down container with resource limits
- Test - run the probe that executed before the fix and confirm it is now refused rather than merely failing differently: for an AST allowlist, `__import__`-style member access or a call node is rejected at parse time; for `vm`, `this.constructor.constructor('return process')().version` returns nothing. Confirm a legitimate expression still evaluates
