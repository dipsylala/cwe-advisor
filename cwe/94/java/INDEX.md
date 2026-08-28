# CWE-94: Improper Control of Generation of Code ('Code Injection') - Java

## LLM Guidance

Code injection in Java occurs when untrusted input is evaluated through scripting engines (`javax.script.ScriptEngine` with JavaScript, Groovy, or MVEL), Groovy's `GroovyShell`, Spring Expression Language against a `StandardEvaluationContext`, or template engines without sandboxing. The `ScriptEngine` API is particularly dangerous because it can be exposed unintentionally through configuration-driven features. Replace dynamic code evaluation with static logic, lookup tables, or a restricted expression evaluator (e.g., Spring Expression Language scoped to read-only property access, not method invocation).

## Key Principles

- Remove or disable `ScriptEngine` access to untrusted input entirely - there is no safe way to sandbox Nashorn/Rhino for arbitrary user expressions
- Replace dynamic script evaluation with predefined logic: switch statements, strategy patterns, or configuration-driven dispatch tables
- If a user-configurable expression language is required, use a purpose-built, sandboxed evaluator (e.g., Apache Commons JEXL with a restricted `JexlSandbox`, or a JEXL `JexlSandbox` built deny-by-default with `new JexlSandbox(false)`). SpEL is not the one to reach for: Spring states that `SimpleEvaluationContext`'s restriction is "provided on a best-effort basis and does not guarantee that expression evaluation is safe", and that evaluating an expression from an untrusted source "is inherently dangerous and should generally be avoided" whichever `EvaluationContext` is used
- Never pass user input to Groovy's `GroovyShell.evaluate()`, `GroovyClassLoader.parseClass()`, or `GroovyScriptEngine`
- Validate and allowlist all inputs strictly before any expression evaluation
- For Spring Expression Language, evaluate against a `SimpleEvaluationContext` rather than a `StandardEvaluationContext`: the standard context permits type references (`T(java.lang.Runtime).getRuntime().exec(...)`), constructors and bean references, and the simple one exposes property access only
- `ScriptEngineManager.getEngineByName("JavaScript")` returns `null` on JDK 15 and later unless a script engine was added back as a dependency, so a finding on that line may be dead code - confirm the runtime before treating it as live, and check whether the null is dereferenced
- Where an engine is genuinely required, restrict what it can reach rather than filtering the script text, and be concrete about what enforces that - a class loader is not a permission boundary, and the SecurityManager that historically supplied one was deprecated for removal by JEP 411 and permanently disabled in JDK 24 by JEP 486. On a current JDK the containment has to come from outside the process: a separate JVM under OS-level limits, or a container

## Taint Sinks

`ScriptEngine.eval()`, `GroovyShell.evaluate()`, `GroovyClassLoader.parseClass()`, `GroovyScriptEngine`, `MVEL.eval()`, `SpelExpressionParser.parseExpression()`, `Expression.getValue()`

## Remediation Steps

- Locate `ScriptEngine.eval(userInput)`, `GroovyShell.evaluate(userInput)`, or similar dynamic compilation calls
- Replace with a lookup table or strategy pattern mapping known-safe identifiers to predefined Java methods
- If a user-visible expression language is a genuine product requirement, evaluate Apache Commons JEXL with `new JexlSandbox(false)` - deny-by-default - and allow only narrow concrete classes by name; `new JexlSandbox(true)` is allow-by-default and still reads as sandboxed in review. Object construction is a separate control: `JexlFeatures.newInstance(false)` passed to `JexlBuilder.features(...)`. Note that `sandbox.allow(...)` grants permission but not reach - an allowed class is callable only if the evaluation context exposes it via `JexlBuilder.namespaces(...)` or a context variable, so an allow entry on its own changes nothing about what the expression can name
- Validate input against a strict allowlist before any evaluation; reject immediately if the input does not match
- Add integration tests that attempt to inject OS commands or class-loading expressions, and assert on the value the evaluation returns: a JEXL sandbox denial evaluates to `null` rather than throwing, so a test asserting that the malicious expression throws passes against a completely unsandboxed engine and proves nothing
- Review build plugins and reflection-heavy frameworks (e.g., BeanShell, MVEL) for similar exposure
