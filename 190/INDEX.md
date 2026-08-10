# CWE-190: Integer Overflow or Wraparound

## LLM Guidance

Integer overflow occurs when an arithmetic operation produces a result larger than its integer type can hold, wrapping the value to a negative or small positive number. When the wrapped result sizes an allocation, a copy length, an index, or a security-relevant count, a value that looked safely large becomes small enough to bypass the check it was meant to satisfy. The fix is to validate operand ranges before the arithmetic runs, or use an operation that detects overflow itself, rather than trusting the result of unchecked arithmetic.

## Key Principles

- Use the platform's overflow-checked arithmetic primitive where one exists, instead of plain +/-/*
- Where no checked operation exists, verify operands are within safe range before the operation, not after
- An overflow check written as a post-hoc comparison on the result can itself be defeated by the same wraparound it is meant to catch; check before the operation, not after
- Use a wider or arbitrary-precision type for calculations whose legitimate range can exceed the native type, then validate the result against a practical application limit
- Reject unreasonably large operands early, independent of whether the arithmetic would technically overflow
- Bounds-check immediately before an indexed access, not based on an earlier calculation that might itself have wrapped

## Remediation Steps

- Locate - Find arithmetic (addition, multiplication) whose result sizes a memory allocation, a copy length, an array index, or a security-relevant count or limit
- Trace data flow - Identify where the operands originate (user input, file/network field, prior calculation) and whether either is attacker-influenced
- Identify the unsafe pattern - Unchecked arithmetic whose result is trusted without a pre-check, or an overflow check performed on the already-wrapped result
- Replace with the safe pattern - Add a pre-check (such as verifying one operand against the type maximum divided by the other) or switch to a checked-arithmetic primitive that signals overflow explicitly
- Add secondary controls - Apply an application-level sanity cap on the result independent of overflow safety, since a non-overflowing value can still be an unreasonable size
- Cover every consumer - Confirm the check applies wherever the result is used, not only the call site a scan finding named
- Test - Verify with boundary values (type maximum, maximum minus one) and values chosen specifically to overflow the operation, confirming the checked path rejects them
