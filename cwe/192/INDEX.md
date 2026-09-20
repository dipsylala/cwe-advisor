# CWE-192: Integer Coercion Error

## LLM Guidance

Not confined to unmanaged code: C and C++ convert implicitly, while Java and C# demand a visible cast that still truncates without complaint - `(int) longValue` keeps the low 32 bits, and C# does the same outside a `checked` block. The language decides where the wrong value surfaces, not whether it is produced. Narrower children carry the specific conversions - losing high-order bits is CWE-197, signed to unsigned is CWE-195, and unsigned to signed is CWE-196.

## Key Principles

- Never let a narrowing or sign-changing conversion happen implicitly; cast explicitly and check the value against the target type's range first
- On a failed range check, reject the value or raise an error rather than silently clamping or truncating, since either substitutes a different but still-incorrect value
- Compare and combine values using one consistent type rather than mixing signed and unsigned; a signed value mixed with an unsigned one is implicitly converted to unsigned, and a negative value becomes very large
- Know which arrangement is actually hazardous: `if (signed_value < unsigned_size)` converts the signed operand and answers *false* for a negative value, skipping the guarded branch - the safe direction, which is why it is easy to miss. The dangerous shape is an upper-bound-only check evaluated in signed arithmetic (`if (len > max) reject`), which accepts a negative `len` that then becomes an enormous value at an unsigned sink such as an allocation or a copy length. Check the sign explicitly before either
- Prefer the language's overflow/range-checked conversion primitives over a bare cast
- Wrap the check-then-cast pattern in a small reusable helper so every conversion site applies the same validation
- Enable and treat as errors the compiler/linter warnings that catch unsafe or implicit numeric conversions

## Remediation Steps

- Locate - Find assignments, casts, or function calls where a wider type crosses into a narrower one, or a signed and unsigned value meet
- Trace data flow - Identify the source of the value being converted and the sink that consumes the converted result (allocation, index, loop bound, comparison)
- Identify the unsafe pattern - An implicit or unchecked conversion, or a bare explicit cast added without a preceding range check
- Replace with the safe pattern - Validate the value against the target type's minimum and maximum before converting, and convert explicitly; reject values that do not fit
- Unify comparison types - Where signed and unsigned values are compared or combined, convert to a single common type first rather than relying on implicit promotion
- Add secondary controls - Audit every caller of a function whose parameter type is narrower than some callers' argument types, not only the flagged call site
- Test - Verify with values at, one above, and one below the target type's range, a negative value where an unsigned parameter is expected, and a value that fits the source type but not the destination
