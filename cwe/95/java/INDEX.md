# CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection') - Java

## LLM Guidance

Java eval injection occurs when untrusted input flows into dynamic code execution mechanisms like scripting engines (Nashorn, Groovy), reflection APIs, or expression languages (SpEL, OGNL, MVEL). While Java lacks a native `eval()`, these components enable runtime code execution. The core fix is eliminating dynamic code execution entirely or using strict allowlists and out-of-process isolation where dynamic execution is unavoidable.

## Key Principles

- Eliminate dynamic evaluation: Replace scripting engines and expression languages with static business logic
- Use allowlists over deny-lists: If dynamic features are required, restrict to predefined safe operations only
- Apply strict input validation: Validate against narrow patterns before any dynamic processing
- Isolate execution contexts: Use separate processes/containers with resource limits; do not rely on Java SecurityManager for modern Java
- Prefer safe alternatives: Use configuration files, domain-specific languages, or rule engines with declarative syntax
- Evaluate Spring expressions against a `SimpleEvaluationContext` rather than a `StandardEvaluationContext`, which permits `T(...)` type references, constructors and bean lookups; in OGNL the equivalent lever is the `MemberAccess` implementation, and the default allows reflection
- `Class.forName()` with a name from the expression turns name selection into code loading, since the class's static initializer runs on load
- Bound the evaluation as well as restricting it: an expression like `while(true){}` is a denial of service that no allowlist of members prevents

## Taint Sinks

`ScriptEngine.eval()`, `ExpressionParser.parseExpression()` (SpEL), `Ognl.getValue()`, reflective `Method.invoke()` with dynamic class/method names

## Remediation Steps

- Identify all uses of ScriptEngine, expression evaluators (SpEL, OGNL), and reflection with user input
- Remove dynamic evaluation and replace with static method calls or lookup maps
- If dynamic features are unavoidable, implement strict allowlist validation of all inputs
- Configure script engine bindings to expose only required, safe objects
- Run unavoidable scripted code in a separate locked-down process/container with minimal privileges and resource limits
- Add automated scanning to detect new eval injection vectors in code reviews
