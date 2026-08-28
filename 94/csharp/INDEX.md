# CWE-94: Improper Control of Generation of Code ('Code Injection') - C#

## LLM Guidance

Code injection in C# occurs when untrusted input is compiled and executed at runtime via the Roslyn scripting API (`CSharpScript.EvaluateAsync`/`RunAsync` in `Microsoft.CodeAnalysis.CSharp.Scripting`), the Roslyn compiler API (`CSharpCodeProvider`, `CSharpCompilation`), the `Microsoft.CSharp.RuntimeBinder`, or dynamic expression evaluators like `NCalc` and `DynamicExpresso` without input restrictions. The Roslyn approach gives attackers full access to the .NET runtime including file system, network, and reflection. Replace runtime compilation with static dispatch logic; if a configurable expression language is unavoidable, use a purpose-built sandboxed evaluator.

## Key Principles

- Never pass user input to `CSharpCodeProvider.CompileAssemblyFromSource()`, `CSharpCompilation.Create()`, or `Assembly.Load()` with user-generated code
- Replace dynamic compilation with predefined delegates, strategy patterns, or configuration-driven dispatch
- If user-configurable formulas are required, use `NCalc` or `DynamicExpresso` with method and type access locked down to a safe allowlist; `DynamicExpresso.Interpreter` has reflection access disabled by default, so do not call `Interpreter.EnableReflection()` for untrusted input, and do not `Reference()` any type that exposes file, process, or reflection APIs
- `ScriptOptions.WithReferences()`/`WithImports()` decide which names the compiler resolves, not what the script may do - reflection loads assemblies at runtime regardless, and `System.Private.CoreLib` alone carries `File`, `Directory` and `Environment`; restricted `AppDomain`s and Code Access Security do not exist on modern .NET, so isolation means a separate process
- Validate all expressions against a strict allowlist of permitted identifiers and operators before evaluation
- Triage a DynamicExpresso finding on which call it actually involves: a default `new Interpreter()` resolves no namespaces and has reflection off, so `System.IO.File.Delete(...)` fails with `UnknownIdentifierException` before anything runs, and a bare interpreter carrying only `SetFunction`/`SetVariable` registrations is usually not the bug - `EnableReflection()` and `Reference(typeof(T))` are what open the type graph
- `SetFunction` adds identifiers rather than confining them: each registered delegate is a hole opened deliberately, so review any that takes a `Type`, reflects on a string argument, or reaches files, processes or the network as a sink in its own right
- Never expose reflection to the expression surface (`GetMethod()`, `Type.GetType()` from a caller-supplied string) - that turns every method in the loaded assemblies into attack surface

## Taint Sinks

`CSharpScript.EvaluateAsync()`, `CSharpScript.RunAsync()`, `CSharpCodeProvider.CompileAssemblyFromSource()`, `CSharpCompilation.Create()`, `Assembly.Load()`, `DynamicExpresso.Interpreter.Eval()`

## Remediation Steps

- Locate `CSharpScript.EvaluateAsync()`/`CSharpScript.RunAsync()`, `CSharpCodeProvider.CompileAssemblyFromSource()`, or `CSharpCompilation` calls that incorporate user input
- Replace with a `Dictionary<string, Func<...>>` dispatch table or a strategy interface pattern
- If a formula evaluator is required, configure `DynamicExpresso.Interpreter` with only the explicitly registered variables and functions, leave reflection disabled (the default - do not call `EnableReflection()`), and avoid referencing `System` namespaces
- Validate input with a regex or parser before passing it to any evaluator
- Run tests injecting `System.IO.File.Delete("/important")` style expressions and confirm they are rejected
- Review NuGet packages that expose scripting APIs and assess whether user input can reach them
