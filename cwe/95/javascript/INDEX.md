# CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection') - JavaScript

## LLM Guidance

JavaScript eval injection occurs when untrusted input flows into dynamic code execution functions like `eval()`, `Function()`, or - in a browser - `setTimeout()`/`setInterval()` with a string. Attackers can execute arbitrary code, access sensitive data, or compromise the application. The sink list and the available mitigations differ between the browser and Node, so establish which runtime the finding is in before fixing it.

## Key Principles

- Eliminate dynamic code execution: Replace `eval()` and `Function()` with static alternatives. `Function()` behaves identically with or without `new`, and while it reaches only the global scope rather than the caller's locals, that is not a security boundary - the constructed function still has `globalThis` and everything reachable from it, including `process` or `require` where those are exposed
- **The string form of `setTimeout`/`setInterval` is browser-only.** In Node these accept a function and nothing else - a string argument throws `TypeError` / `ERR_INVALID_ARG_TYPE` before the timer is scheduled, so a Node finding there is not an eval sink. In a browser the string is compiled and executed, and `setImmediate` is in the same category
- **In Node the eval-equivalent the mitigations miss is `node:vm`.** Its documentation states plainly: "The `node:vm` module is not a security mechanism. Do not use it to run untrusted code." That covers `vm.runInNewContext`, `vm.runInThisContext`, `vm.compileFunction` and `new vm.Script`, and `--disallow-code-generation-from-strings` (v9.8.0+), which does neutralise `eval`/`new Function`, is documented as not affecting it
- Use allowlists: Map user input to predefined functions or values rather than executing strings
- Bracket notation is not automatically the safe replacement. MDN warns against square-bracket access with a key from external input as an object-injection risk, so validate the key against the allowlist of expected properties, or use `Object.hasOwn`/a `Map`, rather than only moving off `eval('obj.' + userInput)`
- Parse safely: Use `JSON.parse()` for data, never `eval()` for JSON. It treats `__proto__` as an ordinary property rather than setting a prototype
- Sanitize module paths: Validate and restrict dynamic `require()` or `import()` calls. `import()` accepts a `data:text/javascript,` URL, which executes the inlined source, and it is reachable from CommonJS as well as ESM
- CSP is a page-wide backstop, not a per-call one: if any other script on the page needs `'unsafe-eval'` - an older charting library, dev-mode bundler output, some WASM setups - the token applies to the whole document and protects none of it, including code that never needed the exemption

## Taint Sinks

`eval()`, `new Function()`, dynamic `require()`/`import()`, `vm.runInNewContext()`/`vm.runInThisContext()`/`vm.compileFunction()`/`new vm.Script()` (Node), `setTimeout(string, ...)`/`setInterval(string, ...)`/`setImmediate(string)` (browser)

## Remediation Steps

- Search the codebase for `eval()`, `Function()`, dynamic `require()`/`import()`, and `vm.*`; add string-argument `setTimeout`/`setInterval` only for browser code
- Replace `eval(json)` with `JSON.parse(json)`
- Convert dynamic property access to a validated lookup - an allowlist, a `Map`, or an own-property check - rather than a bare `obj[userInput]`
- Refactor string-based function calls to object mappings or switch statements
- For unavoidable cases, validate input against strict allowlists before execution
- In Node, run `--disallow-code-generation-from-strings` and move anything relying on `node:vm` for isolation into a separate process or container
- In the browser, set a CSP `script-src` (or `default-src`) and do not add `'unsafe-eval'`: string compilation is blocked once the directive is present, and `'unsafe-eval'` is the token that re-enables it for `eval`, `Function`, and string timers alike. Check the whole policy, not just this feature's needs
