# CWE-787: Out-of-bounds Write - C

## LLM Guidance

C performs no bounds checking on array access or pointer arithmetic, so a write lands wherever the index or pointer says regardless of what was allocated. The recurring causes are copy and format functions with no destination-size parameter (`strcpy`, `strcat`, `sprintf`, `gets`), size calculations that overflow before an allocation, and off-by-one loop bounds. Replace the unbounded call with a size-aware equivalent and validate every write's offset and length against the destination's real capacity - never against a length field taken from the input itself.

## Key Principles

- Where the destination lives decides the blast radius, not whether the bug exists: a file-scope buffer overflows into other objects in static storage, while the same buffer as a local overflows the saved frame pointer and return address, which is CWE-121. The missing check and the fix are identical
- Use `snprintf` for formatted output and `strlcpy`/`strlcat` (BSD, macOS, glibc 2.38+) for copies; both report the length they would have needed, so truncation is detectable rather than silent - compare the return value against `sizeof(dest)` and treat a value at or above it as failure
- Where `strlcpy` is unavailable, the portable fallback is `strncpy(dest, src, sizeof(dest) - 1)` followed by an explicit `dest[sizeof(dest) - 1] = '\0'` - `strncpy` alone does not NUL-terminate when the source fills the length argument
- Treat the `strn*` family as a fallback rather than a first choice: each member measures its size argument from a different point, and `strncat`'s third argument is the space remaining, not the buffer's capacity
- Check the multiplication before allocating: `if (count > SIZE_MAX / sizeof(int)) return NULL;` detects the overflow that would otherwise wrap the size down to a small allocation the following loop writes past. `calloc()` and `reallocarray()` perform this check internally and are preferable to a hand-rolled multiply
- Validate `offset <= buf_len` first and then `length <= buf_len - offset`, in that order, so the subtraction cannot underflow
- Valid indices are `0` to `size - 1`: a loop written `i <= size` writes one element past the end of every buffer it touches
- `_FORTIFY_SOURCE` and stack canaries are hardening layers that catch mistakes where the size is statically known; they are not a substitute for the check

## Taint Sinks

`strcpy()`, `strcat()`, `sprintf()`, `vsprintf()`, `gets()`, `memcpy()`/`memmove()` with an unvalidated length, array indexing and pointer arithmetic with an unvalidated index

## Remediation Steps

- Locate - search for the unbounded copy/format functions, `memcpy` calls whose length is not a constant, and loops that index a buffer
- Trace data flow - identify where the index, offset, length, or element count originates, and whether the destination's real capacity is known at that point
- Identify the unsafe pattern - a write whose size comes from the source or from a length field in the data, an `i <= size` loop bound, or an unchecked `count * sizeof(T)` before allocation
- Replace with the safe pattern - `snprintf`/`strlcpy` with `sizeof(dest)`, an explicit length check before `memcpy`, and `calloc`/`reallocarray` for element-count allocations
- Bind, encode, validate, or authorize - clamp the length to the smaller of the source's available bytes and the destination's capacity, and reject rather than truncate when it does not fit
- Harden configuration - build with `-Wall -Wextra -Wformat-security -D_FORTIFY_SOURCE=2` at `-O1` or higher (glibc activates it only when `__OPTIMIZE__` is set, so at `-O0` it silently adds nothing)
- Test - run under `-fsanitize=address,undefined` and Valgrind with normal, exactly-capacity, and oversized inputs, and fuzz any parser of untrusted input; confirm from the sanitizer output that no out-of-bounds write occurred
