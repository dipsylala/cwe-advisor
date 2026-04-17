# CWE-94: Code Injection - Java

## LLM Guidance

Code injection in Java occurs when untrusted input is evaluated through scripting engines (`javax.script.ScriptEngine` with JavaScript, Groovy, or MVEL), passed to `Runtime.exec()` as a script, or interpreted via template engines without sandboxing. The `ScriptEngine` API is particularly dangerous because it can be exposed unintentionally through configuration-driven features. Replace dynamic code evaluation with static logic, lookup tables, or a restricted expression evaluator (e.g., Spring Expression Language scoped to read-only property access, not method invocation).

## Key Principles

- Remove or disable `ScriptEngine` access to untrusted input entirely — there is no safe way to sandbox Nashorn/Rhino for arbitrary user expressions
- Replace dynamic script evaluation with predefined logic: switch statements, strategy patterns, or configuration-driven dispatch tables
- If a user-configurable expression language is required, use a purpose-built, sandboxed evaluator (e.g., Apache Commons JEXL with a restricted `Sandbox`, or SpEL with method-invocation disabled)
- Never pass user input to Groovy's `GroovyShell.evaluate()`, `GroovyClassLoader.parseClass()`, or `GroovyScriptEngine`
- Validate and allowlist all inputs strictly before any expression evaluation

## Remediation Steps

- Locate `ScriptEngine.eval(userInput)`, `GroovyShell.evaluate(userInput)`, or similar dynamic compilation calls
- Replace with a lookup table or strategy pattern mapping known-safe identifiers to predefined Java methods
- If a user-visible expression language is a genuine product requirement, evaluate Apache Commons JEXL with a `JexlSandbox` restricting class and method access; disable `new` operator and system class access
- Validate input against a strict allowlist before any evaluation; reject immediately if the input does not match
- Add integration tests that attempt to inject OS commands or class-loading expressions and confirm they are rejected
- Review build plugins and reflection-heavy frameworks (e.g., BeanShell, MVEL) for similar exposure

## Safe Pattern

```java
import java.util.Map;
import java.util.function.Function;

// SAFE: lookup table replaces dynamic evaluation
private static final Map<String, Function<Integer, Integer>> OPERATIONS = Map.of(
    "double",   x -> x * 2,
    "square",   x -> x * x,
    "negate",   x -> -x
);

public int applyOperation(String opName, int value) {
    Function<Integer, Integer> op = OPERATIONS.get(opName);
    if (op == null) {
        throw new IllegalArgumentException("Unknown operation: " + opName);
    }
    return op.apply(value);
}
```
