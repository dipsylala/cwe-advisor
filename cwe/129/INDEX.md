# CWE-129: Improper Validation of Array Index

## LLM Guidance

Improper validation of array index occurs when user-controlled or untrusted data is used as an array index without proper bounds checking, allowing attackers to read or write arbitrary memory locations, leak sensitive data, or cause crashes. The core fix is to validate array indices before use, including checks for negative and overflowed values.

## Key Principles

- Validate all array indices before use, checking both negative and overflowed values
- Always verify both lower bound (>= 0) and upper bound (< array.length): an upper-bound-only check lets a negative index through wherever both operands are signed (Java and C# `length` is an `int`, and any C bound held in an `int`). A C bound of type `size_t` rejects it only by accident of the conversion, and that protection disappears as soon as the check becomes a range check on `offset + length`
- Validate signed input before any conversion to unsigned index types
- Reject invalid indices immediately rather than attempting correction - clamping to the nearest valid index processes another record as though the request had been valid, and gives neither the caller nor an attacker probing boundaries any signal
- Re-validate after any arithmetic: checking `index` and then computing `base + index` or `index * element_size` reopens the gap, since the calculation can overflow into an in-range-looking value
- Bound the index against the array's *actual* allocated size, not against a length or count field that arrived from the same untrusted source
- Trace data flow from untrusted sources to array access points

## Remediation Steps

- Review security findings to identify where untrusted data is used as an array index
- Locate the array access and identify the index source (user input, external file, database, network request)
- Trace the data flow from source to array access to understand the complete path
- Implement bounds checking - ensure `index >= 0 && index < array.length` before every access
- In C/C++, validate `index >= 0 && index < length` before converting to `size_t` or other unsigned index types
- Reject invalid indices with appropriate error handling rather than clamping or wrapping
