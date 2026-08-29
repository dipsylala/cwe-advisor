# CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection') - Java

## LLM Guidance

Java eval injection occurs when untrusted input flows into dynamic code execution mechanisms like scripting engines (Nashorn, Groovy, Jython, GraalVM), reflection APIs, or expression languages (SpEL, OGNL, MVEL). While Java lacks a native `eval()`, these components enable runtime code execution. The core fix is eliminating dynamic code execution entirely or using strict allowlists and out-of-process isolation where dynamic execution is unavoidable.

## Key Principles

- Eliminate dynamic evaluation: Replace scripting engines and expression languages with static business logic
- Use allowlists over deny-lists: If dynamic features are required, restrict to predefined safe operations only
- Apply strict input validation: Validate against narrow patterns before any dynamic processing
- Isolate execution contexts: Use separate processes/containers with resource limits. The Security Manager is not an option - deprecated for removal in JDK 17 (JEP 411), disabled by default from 18, and permanently disabled in JDK 24 (JEP 486), where enabling it aborts the JVM
- Nashorn shipped in the JDK for 8-14 only: deprecated for removal in 11 (JEP 335), removed in 15 (JEP 372). Its absence is not a fix, because it remains available as the maintained standalone artifact `org.openjdk.nashorn:nashorn-core`, and GraalVM supplies an engine too. Check the manifest rather than the JDK version: `ScriptEngineManager.getEngineByName("JavaScript")` returning `null` makes the call an NPE rather than execution, which changes how the finding is recorded, not whether the code is fixed
- A script engine is not a sandbox and was never sold as one - Nashorn exposed the whole JVM by design, so `java.lang.Runtime` is reachable from script without any escape. `eval()` also takes no timeout, and a script language *does* have loops, so `while(true){}` holds a request thread indefinitely even where nothing sensitive is reachable
- **`SimpleEvaluationContext` is a reduction, not a boundary.** Spring's own javadoc: it "must not be considered safe for evaluating a SpEL expression obtained from an untrusted source", and the restriction is "provided on a best-effort basis". It excludes Java type references, constructors and bean references (`@since 4.3.15`), which is worth having - but the reference documentation says evaluating an untrusted expression is dangerous "regardless of which `EvaluationContext` implementation is used". CVE-2026-41852 is the demonstration: arbitrary zero-argument method invocation even in restricted contexts, fixed in 6.2.19/7.0.8
- The SpEL defect is usually an omission rather than a wrong choice: `Expression.getValue()` called with no `EvaluationContext` falls back to `StandardEvaluationContext`, which is what makes `T(java.lang.Runtime)` resolve. Nothing at the call site reads as a security decision, so search for the no-argument form
- In OGNL the equivalent lever is the `MemberAccess` implementation, but the modern default is narrower than it is often described: `DefaultMemberAccess` was removed in OGNL 3.2.2, and `Ognl.createDefaultContext` now installs an accessor permitting public members only. That still leaves `@java.lang.Runtime@getRuntime()`, since OGNL's `@class@method` syntax reaches statics with no object graph to traverse. `SecurityMemberAccess`, the allowlisting one, comes from Struts rather than OGNL core - as do `struts.allowlist.enable` (6.4+, default in 7.0) and the OGNL Guard. Struts' denylist has been bypassed repeatedly (S2-045, S2-057), so where the expression comes from a request, stop evaluating it rather than filtering it
- `Class.forName()` with a name from the expression turns name selection into code loading, since loading with initialization runs the class's static initializer. The three-argument form with `initialize=false` obtains the `Class` without that
- Bound the evaluation as well as restricting it, using the vendor's own limits. SpEL has no loop construct, so its denial of service is expression complexity rather than iteration: cap it with `maxExpressionLength` (10,000, `@since 5.2.24`) and `maxOperations` (10,000, `@since 6.2.19`, added for CVE-2026-41850), or the properties `spring.context.expression.maxLength` and `spring.expression.maxOperations`. Struts caps OGNL separately with `struts.ognl.expressionMaxLength`, default 256

## Taint Sinks

`ScriptEngine.eval()`, `ExpressionParser.parseExpression()` and `Expression.getValue()` (SpEL), `Ognl.getValue()`, reflective `Method.invoke()` with dynamic class/method names

## Remediation Steps

- Identify all uses of ScriptEngine, expression evaluators (SpEL, OGNL), and reflection with user input
- Remove dynamic evaluation and replace with static method calls or lookup maps - the expression string itself must not come from a request, since context restriction does not make one safe
- If dynamic features are unavoidable, implement strict allowlist validation of all inputs
- Configure script engine bindings to expose only required, safe objects, and set the expression length and operation limits above
- Run unavoidable scripted code in a separate locked-down process/container with minimal privileges and resource limits
- Check the manifest, not the runtime - a removed JDK engine can be back as a dependency
- Add automated scanning to detect new eval injection vectors in code reviews
