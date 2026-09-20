# CWE-94: Improper Control of Generation of Code ('Code Injection') - C#

## LLM Guidance

Code injection in C# occurs when untrusted input is compiled and executed at runtime via the Roslyn scripting API (`CSharpScript.EvaluateAsync`/`RunAsync` in `Microsoft.CodeAnalysis.CSharp.Scripting`), `CSharpCompilation`, the `Microsoft.CSharp.RuntimeBinder`, or dynamic expression evaluators like `NCalc` and `DynamicExpresso` without input restrictions. `CSharpCodeProvider.CompileAssemblyFromSource()` is a legacy .NET Framework API only - on .NET Core and .NET 5+ it throws `PlatformNotSupportedException` unconditionally, so a finding naming it is only live if the project actually targets .NET Framework, not if it targets a modern TFM. No Roslyn API sandboxes execution by default - per Roslyn's own maintainers, the only reliable isolation is a separate process with limited permissions. Replace runtime compilation with static dispatch logic; if a configurable expression language is unavoidable, use a purpose-built sandboxed evaluator.

## Key Principles

- Never pass user input to `CSharpCompilation.Create()` or `Assembly.Load()` with user-generated code; on a .NET Framework target, the same applies to `CSharpCodeProvider.CompileAssemblyFromSource()` - confirm the project's target framework before treating this API as live, since it fails with `PlatformNotSupportedException` on .NET Core/5+
- Replace dynamic compilation with predefined delegates, strategy patterns, or configuration-driven dispatch
- If user-configurable formulas are required, `DynamicExpresso.Interpreter` has reflection access disabled by default - do not call `Interpreter.EnableReflection()` for untrusted input, and do not `Reference()` any type that exposes file, process, or reflection APIs. `NCalc` has no equivalent named allowlist or reflection toggle; its containment is structural. Take `NCalc.Core` 6.1.1 or later - the package the others redirect to - which fixes CVE-2026-55254, a non-terminating factorial evaluation reachable from exactly the untrusted expressions this path is for, and keep a timeout around the evaluation regardless - its expression grammar has no member-access or reflection syntax at all - so a finding there is about what custom functions the application registers, not a configuration to lock down
- `ScriptOptions.WithReferences()`/`WithImports()` decide which names the compiler resolves, not what the script may do - reflection loads assemblies at runtime regardless, and `System.Private.CoreLib` alone carries `File`, `Directory` and `Environment`; restricted `AppDomain`s and Code Access Security do not exist on modern .NET, so isolation means a separate process
- `DynamicExpresso.Interpreter.Reference(typeof(T))` is all-or-nothing: allowlisting one type exposes every public member on it, not just the ones the application intends to use
- Triage a DynamicExpresso finding on which call it actually involves: a default `new Interpreter()` resolves no namespaces and has reflection off, so `System.IO.File.Delete(...)` fails with `UnknownIdentifierException` before anything runs, and a bare interpreter carrying only `SetFunction`/`SetVariable` registrations is usually not the bug - `EnableReflection()` and `Reference(typeof(T))` are what open the type graph
- `SetFunction` adds identifiers rather than confining them: each registered delegate is a hole opened deliberately, so review any that takes a `Type`, reflects on a string argument, or reaches files, processes or the network as a sink in its own right
- Never expose reflection to the expression surface (`GetMethod()`, `Type.GetType()` from a caller-supplied string) - that turns every method in the loaded assemblies into attack surface

## Taint Sinks

`CSharpScript.EvaluateAsync()`, `CSharpScript.RunAsync()`, `CSharpCompilation.Create()`, `Assembly.Load()`, `DynamicExpresso.Interpreter.Eval()`, `CSharpCodeProvider.CompileAssemblyFromSource()` (only on a .NET Framework target - throws `PlatformNotSupportedException` on .NET Core/5+)

## Remediation Steps

- Locate `CSharpScript.EvaluateAsync()`/`CSharpScript.RunAsync()` or `CSharpCompilation` calls that incorporate user input; also check `CSharpCodeProvider.CompileAssemblyFromSource()` if the project targets .NET Framework, since on .NET Core/5+ that call always throws `PlatformNotSupportedException`, making the finding there a crashing endpoint rather than a live sink
- Replace with a `Dictionary<string, Func<...>>` dispatch table or a strategy interface pattern
- If a formula evaluator is required, configure `DynamicExpresso.Interpreter` with only the explicitly registered variables and functions, leave reflection disabled (the default - do not call `EnableReflection()`), and avoid referencing `System` namespaces
- Cap the expression length, and validate its form only where the application defines that form - a regex over formula text invented for the fix rejects legitimate formulas
- Test with a probe that discriminates. `System.IO.File.Delete(...)` is the right shape for the `CSharpScript` path, but against DynamicExpresso it is refused before the fix as well - a default `Interpreter` resolves no namespaces - so it proves nothing there. For that path assert that `x.GetType().Assembly` raises `ReflectionNotAllowedException`, which is what distinguishes reflection-off from an interpreter someone called `EnableReflection()` on
- Review NuGet packages that expose scripting APIs and assess whether user input can reach them
