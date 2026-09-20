# CWE-193: Off-by-one Error

## LLM Guidance

In native code this lands as an out-of-bounds read (CWE-125) or write (CWE-787), and a finding will usually be filed as one of those; in a managed language it raises an index exception or quietly produces a wrong result instead.

## Key Principles

- A collection of size N has valid indices 0 through N-1; every loop bound and boundary check must use a strict less-than comparison against size, never less-than-or-equal
- Any allocation that will hold a null terminator, sentinel, or extra delimiter must be sized as data length plus the extra positions the terminator needs
- Prefer range-based/foreach iteration or a built-in length-tracking collection over manually computed loop bounds, which removes the calculation entirely
- Where a manual index is unavoidable, prefer a checked-access method over an unchecked one
- For reverse iteration over an unsigned counter, decrement inside the loop condition rather than comparing against zero with a non-strict operator, which is always true after wraparound
- A length or count value that travels with untrusted data still needs the same strict boundary check as any other index, not an assumption of correctness

## Remediation Steps

- Locate - Find loop conditions, boundary checks, and allocations tied to a collection or buffer size
- Trace data flow - Identify where the size value originates and every place it is used as a loop bound, index check, or allocation size
- Identify the unsafe pattern - A less-than-or-equal comparison against size where strict less-than belongs, or an allocation sized to exactly the data length when a terminator or sentinel needs one more
- Replace with the safe pattern - Change inclusive comparisons to exclusive ones against size, and add the extra element to allocations that need a terminator or sentinel
- Audit sibling code - Check the same function and related code for other accesses to the same collection using the same wrong comparison
- Add secondary controls - Prefer checked-access methods that throw or refuse on an out-of-range index over unchecked ones
- Test - Verify with size-0 and size-1 collections, the last valid index and the first invalid one, and data exactly at allocated capacity and one element over
