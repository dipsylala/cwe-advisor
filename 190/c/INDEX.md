# CWE-190: Integer Overflow or Wraparound - C

## LLM Guidance

Signed integer overflow in C is undefined behavior, not defined wraparound - a compiler may assume it never happens and optimize away a check written after the arithmetic, so the check must run before the operation, not after. The current preferred approach is a compiler builtin such as `__builtin_add_overflow()` or `__builtin_mul_overflow()` (GCC/Clang), which performs the operation and reports overflow without relying on the UB it is checking for; where builtins are unavailable, use an explicit precondition check sized to the operand types. The highest-impact case is an overflowed or wrapped size or length value that then sizes a `malloc()`/`calloc()` allocation or a `memcpy()` length, since a value that looked safely large becomes small enough to cause a heap buffer overflow later.

## Key Principles

- Signed integer overflow is undefined behavior in C; never check for it by testing the result after the operation, since the compiler may remove a post-hoc check as unreachable
- Perform the overflow check before the arithmetic runs, using a precondition test appropriate to the operand types and signs
- Prefer `__builtin_add_overflow()`, `__builtin_sub_overflow()`, and `__builtin_mul_overflow()` (GCC and Clang) over hand-written precondition logic - they compute the correct result and a true/false overflow flag in one step, handle mixed-sign operands correctly, and cannot be optimized away by the UB they check for
- Unsigned (`size_t`) arithmetic wraps instead of triggering UB, but a wrapped `size_t` is just as dangerous when it sizes an allocation or copy length; precondition-check `size_t` arithmetic that feeds `malloc`/`calloc`/`memcpy` the same as signed arithmetic
- Treat any overflowed or wrapped length that reaches `malloc()`, `calloc()`, or `memcpy()` as a buffer-overflow risk, not merely an arithmetic bug - validate before the allocation, not after
- Where builtins are unavailable, use `<limits.h>`/`<stdint.h>` constants (`INT_MAX`, `SIZE_MAX`) to size the precondition check to the actual operand type - for a multiplication that is `elem_size != 0 && count > SIZE_MAX / elem_size` before the multiply - and prefer `calloc(count, size)` over `malloc(count * size)` since `calloc` performs its own overflow check on the multiplication

## Taint Sinks

`malloc()`, `calloc()`, `realloc()`, `memcpy()`, `memmove()` sized by unchecked arithmetic, array indexing from unchecked arithmetic

## Remediation Steps

- Locate - Find addition or multiplication whose result sizes a `malloc`/`calloc`/`realloc` call, a `memcpy`/`memmove` length, an array index, or another security-relevant count
- Trace data flow - Identify whether either operand originates from user input, a file/network field, or a prior calculation, and whether the type is signed or unsigned
- Identify the unsafe pattern - Unchecked arithmetic feeding an allocation or copy size, or an overflow check performed on the already-computed (and possibly already-UB) result
- Replace with the safe pattern - Add a precondition check before the operation, or replace the operation with `__builtin_add_overflow()`/`__builtin_mul_overflow()` and reject when it returns true
- Bind, encode, validate, or authorize - Use the checked, validated value everywhere the result feeds `malloc`/`calloc`/`memcpy`, not the original unchecked operands
- Harden configuration - Compile with `-fsanitize=undefined` (or `-ftrapv`) during testing to catch any signed overflow a manual check missed
- Test - Test with `INT_MAX`/`SIZE_MAX`, values one below and above those limits, and operand pairs specifically chosen to overflow the addition/multiplication, confirming the checked path rejects them before any allocation occurs
