# CWE-470: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')

## LLM Guidance

Unsafe reflection occurs when applications use untrusted input to select classes, methods, or code via reflection APIs (Class.forName, eval, import), enabling arbitrary code execution and complete application compromise. Never allow untrusted input to directly select classes/types/methods for execution.

## Key Principles

- Allowlist over blacklist: Define explicit permitted classes/methods; reject all others
- Indirect mapping: Map user input to safe identifiers, not class/method names directly
- Avoid reflection: Use polymorphism, factory patterns, or strategy patterns instead
- Input validation: If reflection required, validate against strict allowlist before use
- Least privilege: Restrict reflection to minimum required classes/methods
- Bind names to classes rather than checking them: a `Map<String, Class<?>>` keyed by the value the caller sends means no reflection API ever sees attacker input, and there is nothing for a permitted-name list and a resolver to drift apart about
- Reject a null or blank value *before* the lookup: `Map.of(...)` is null-hostile, so `ALLOWED.get(userInput)` throws `NullPointerException` for an absent parameter and the null check written on the next line never runs - an omitted parameter becomes a 500
- The boundary with code injection is whether the attacker supplies a *name* or a *program*: `engine.eval(userScript)` is CWE-95 even though a script engine is involved, while `engine.get(userFunctionName)` is this weakness
- An attacker who can also add to the classpath, or write into a directory already on it, escalates name selection into loading their own code (CWE-426/CWE-427)

## Remediation Steps

- Locate vulnerability - Review scan data_paths to find where untrusted input flows to `Class.forName()`, `getMethod()`, `eval()`, `ScriptEngine.eval()`, or dynamic imports
- Map to allowlist - Create `Map<String, Class<?>>` mapping safe identifiers to permitted classes; reject unmapped input
- Use factory pattern - Replace reflection with factory that returns instances based on allowlisted types
- Validate strictly - If reflection unavoidable, validate input against allowlist before `Class.forName()` or `getMethod()`
- Remove eval - Replace `eval()` and script engines with type-safe alternatives
- Test coverage - Verify malicious class names (e.g., `java.lang.Runtime`, `ProcessBuilder`) are rejected
