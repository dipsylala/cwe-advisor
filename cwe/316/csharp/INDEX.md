# CWE-316: Cleartext Storage of Sensitive Information in Memory - C#

## LLM Guidance

Storing sensitive data (passwords, keys, tokens) as cleartext strings in C# memory exposes them to memory dumps, debuggers, and disclosure attacks. Immutable strings persist until garbage collection, creating extended exposure windows. Prefer `char[]` or `byte[]` with explicit clearing, external credential stores, and credential handles; use `SecureString` only for legacy APIs that require it.

## Key Principles

- Replace `string` with mutable `char[]` or `byte[]` for sensitive data to enable immediate zeroing
- Clear sensitive arrays explicitly in `finally` blocks using `CryptographicOperations.ZeroMemory(Span<byte>)`, not `Array.Clear()` - Microsoft documents `ZeroMemory` as existing specifically "to future-proof against potential optimizations in the .NET runtime that could eliminate memory writes that aren't followed by memory reads," a risk `Array.Clear()` does not guard against
- A regular managed array is not pinned, so a compacting GC can copy it to a new address before your `finally` block runs - the same relocation the root CWE-316 guidance describes generically applies concretely here: `SecureString`'s docs contrast its own pinned buffer against ordinary strings/arrays, which the GC "will make additional copies of ... when moving and compacting memory." Zeroing the array you can reach does not reach a pre-compaction copy
- Minimize sensitive data lifetime in memory-clear immediately after use
- Use external credential stores or OS credential handles where possible; avoid introducing `SecureString` in new .NET code unless a legacy API requires it - Microsoft's own guidance (analyzer rule DE0001) recommends against it for new development
- Avoid serialization, logging, or concatenation of sensitive data

## Taint Sinks

`string` fields/variables/parameters holding passwords, keys, or tokens; `SecureString` in new code; `Array.Clear()` used where `CryptographicOperations.ZeroMemory()` is available

## Remediation Steps

- Identify all sensitive data stored as `string` (passwords, keys, tokens)
- Replace with `char[]` or `byte[]` and refactor dependent code
- Wrap usage in `try/finally` with `CryptographicOperations.ZeroMemory()` in the `finally` block
- For a BSTR obtained via `Marshal.SecureStringToBSTR()`, free it with the matching `Marshal.ZeroFreeBSTR()` rather than a generic free - it is paired to that one allocation method, not a general-purpose unmanaged-memory zeroer; use `SafeHandle` for other unmanaged resources
- Review logging, exception messages, and serialization for leakage
- Test with memory profilers to verify clearance
