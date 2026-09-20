# CWE-190: Integer Overflow or Wraparound

## LLM Guidance

The wrapped result is small where the true value was large, so a bound check written for the true value passes it. Confirm which boundary the calculation crosses - a subtraction falling below the minimum is CWE-191, and an unsafe *conversion* producing an unexpected value is CWE-192/195/196/197; the families chain together but the fixes differ.

## Key Principles

- Use the platform's overflow-checked arithmetic primitive where one exists, instead of plain +/-/*
- Where no checked operation exists, verify operands are within safe range before the operation, not after
- An overflow check written as a post-hoc comparison on the result can itself be defeated by the same wraparound it is meant to catch; check before the operation, not after. `if (a + b < a)` does detect the wrap where it is *defined* - any unsigned type, and signed `int`/`long` in Java or unchecked C# - but on a signed type in C or C++ the addition is undefined behaviour, so the compiler may conclude the branch is unreachable and delete it: the guard is in the source and not in the binary
- Use a wider or arbitrary-precision type for calculations whose legitimate range can exceed the native type, then validate the result against a practical application limit
- Reject unreasonably large operands early, independent of whether the arithmetic would technically overflow, and validate the *result* of the calculation rather than only each operand - several individually reasonable fields can still combine into an overflow
- Ship the checked path, do not merely test it: a sanitizer or checked-arithmetic debug mode that is not in the release build leaves production exactly as it was
- Bounds-check immediately before an indexed access, not based on an earlier calculation that might itself have wrapped

## Remediation Steps

- Locate - Find arithmetic (addition, multiplication) whose result sizes a memory allocation, a copy length, an array index, or a security-relevant count or limit
- Trace data flow - Identify where the operands originate (user input, file/network field, prior calculation) and whether either is attacker-influenced
- Identify the unsafe pattern - Unchecked arithmetic whose result is trusted without a pre-check, or an overflow check performed on the already-wrapped result
- Replace with the safe pattern - Add a pre-check (such as verifying one operand against the type maximum divided by the other) or switch to a checked-arithmetic primitive that signals overflow explicitly
- Add secondary controls - Apply an application-level sanity cap on the result independent of overflow safety, since a non-overflowing value can still be an unreasonable size
- Cover every consumer - Confirm the check applies wherever the result is used, not only the call site a scan finding named
- Test - Verify with boundary values (type maximum, maximum minus one) and values chosen specifically to overflow the operation, confirming the checked path rejects them
