# CWE-94: Code Injection - C# / .NET

## LLM Guidance

Code injection in C# occurs when untrusted input is compiled and executed at runtime via the Roslyn compiler API (`CSharpCodeProvider`, `CSharpCompilation`), the `Microsoft.CSharp.RuntimeBinder`, or dynamic expression evaluators like `NCalc` and `DynamicExpresso` without input restrictions. The Roslyn approach gives attackers full access to the .NET runtime including file system, network, and reflection. Replace runtime compilation with static dispatch logic; if a configurable expression language is unavoidable, use a purpose-built sandboxed evaluator.

## Key Principles

- Never pass user input to `CSharpCodeProvider.CompileAssemblyFromSource()`, `CSharpCompilation.Create()`, or `Assembly.Load()` with user-generated code
- Replace dynamic compilation with predefined delegates, strategy patterns, or configuration-driven dispatch
- If user-configurable formulas are required, use `NCalc` or `DynamicExpresso` with method and type access locked down to a safe allowlist
- Restrict `AppDomain` / sandbox environments — they do not reliably prevent code injection on modern .NET runtimes
- Validate all expressions against a strict allowlist of permitted identifiers and operators before evaluation

## Remediation Steps

- Locate `CSharpCodeProvider.CompileAssemblyFromSource()` or `CSharpCompilation` calls that incorporate user input
- Replace with a `Dictionary<string, Func<...>>` dispatch table or a strategy interface pattern
- If a formula evaluator is required, configure `DynamicExpresso.Interpreter` with only the explicitly registered variables and functions, and disable access to `System` namespaces
- Validate input with a regex or parser before passing it to any evaluator
- Run tests injecting `System.IO.File.Delete("/important")` style expressions and confirm they are rejected
- Review NuGet packages that expose scripting APIs and assess whether user input can reach them

## Safe Pattern

```csharp
using System.Collections.Generic;

// SAFE: dispatch table — no dynamic compilation
private static readonly Dictionary<string, Func<double, double>> _ops = new()
{
    ["double"]  = x => x * 2,
    ["square"]  = x => x * x,
    ["negate"]  = x => -x,
};

public double ApplyOperation(string opName, double value)
{
    if (!_ops.TryGetValue(opName, out var op))
        throw new ArgumentException($"Unknown operation: {opName}");
    return op(value);
}

// SAFE: DynamicExpresso with locked-down scope (if scripting is genuinely needed)
// using DynamicExpresso;
// var interpreter = new Interpreter(InterpreterOptions.Default);
// interpreter.SetVariable("x", userValue);  // Only known-safe variables
// // Do NOT call interpreter.Reference(typeof(System.IO.File)) or similar
// double result = interpreter.Eval<double>("x * 2");  // Operator only — no method calls
```
