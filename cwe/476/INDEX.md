# CWE-476: NULL Pointer Dereference

## LLM Guidance

A null pointer dereference happens when code reads, writes, or calls through a pointer, reference, or object handle that turns out to be null, nil, or None, causing a crash or, in unmanaged languages, undefined behavior. It typically stems from a value that can legitimately be null - a failed lookup, an uninitialized field, an optional return, an unchecked external response - being used without first confirming it is present. The fix is not just a check at the crash site; trace the value back to where it can become null and decide whether to fix the producer's contract or handle the absence at every call site that can receive it. Where the language has null-safety features (non-nullable types, optional/option wrappers, compiler-enforced nil checks), prefer those over manual runtime checks.

## Key Principles

- Distinguish a real fix from a symptom patch: a check that stops the crash but then proceeds with a default or partially-initialized value can silently produce incorrect behavior instead of a clean failure
- When a function can legitimately return or hold null, that is a contract problem - every caller needs to handle it, not just the one that crashed first
- Prefer language and type-system features that make nullability explicit and checked at compile time (non-nullable reference types, Optional/Option-style wrappers, mandatory nil checks) over ad hoc runtime guards
- Initialize variables, fields, and collections to a valid state at declaration or construction rather than leaving them null until first use
- Handle absence explicitly: return early, raise a meaningful error, or supply a documented default, rather than a check that swallows the missing-value case
- Apply defence-in-depth: use static analysis or the compiler's null-safety diagnostics to catch dereferences the review misses, and let a genuinely unexpected null fail loudly rather than continue silently
- A null return is usually the function reporting truthfully that nothing was found; the defect is that the return type gives that answer the same shape as a real one, so the caller can use it without deciding what to do about it
- Handle the absence where the null-capable value is *produced*, not only at the call site where the crash was observed - the same producer usually has several callers
- Make the unchecked path a compile-time error where the language allows it, with a non-nullable type or an `Optional`-style wrapper, rather than relying on a review to spot the missing check

## Remediation Steps

- Locate - identify the exact dereference, member access, method call, or index operation that fails, and the variable holding the null value
- Trace data flow - follow that value backward through assignments, return paths, and parameter passing to find every place it can become null or absent
- Determine the fix point - decide whether null should never have reached this point (fix the producer or contract) or whether this is a legitimate optional value this consumer must handle
- Apply the fix - add a null check with explicit handling (early return, error, or safe default) at the correct point, or change the type/contract so the compiler enforces presence, rather than checking only where the crash was observed
- Audit sibling call sites - if the null-producing function or field has other callers, confirm they handle the same case; a fix at one crash site leaves the others exposed
- Add secondary controls - enable the language or platform's null-safety analysis (nullable reference type checking, Optional-returning APIs, static analyzer null-dereference rules) to catch regressions
- Test - exercise the code path with the value absent, empty, and present, including any external or asynchronous source that can return null unexpectedly, and confirm the failure is a controlled error rather than a crash or silent bad state
