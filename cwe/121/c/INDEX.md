# CWE-121: Stack-based Buffer Overflow - C

## LLM Guidance

A C stack buffer is a local array with no runtime awareness of its own size: `char buffer[64]` tells the compiler how much space to reserve, and nothing stops `strcpy(buffer, input)` writing 200 bytes into it. The causes are copy and format functions with no destination-size parameter (`gets`, `strcpy`, `strcat`, `sprintf`) and manual loops with an off-by-one or an unchecked source length. Replace the unbounded call with a size-aware equivalent (`fgets`, `snprintf`, `strlcpy`/`strlcat` where available) and validate the input length against the destination's real declared size before copying.

## Key Principles

- `gets()` has no size parameter and no safe call - it was removed from the standard library in C11; replace it with `fgets(buf, sizeof buf, stdin)`
- `fgets` closes the overflow and leaves truncation behind: an over-long line is split, and the tail is read as the next line. A missing trailing newline in the buffer does not by itself prove truncation - the line can legitimately end exactly at the buffer's capacity, with only the newline itself left unread. Peek the next character with `getchar()`: `EOF` or `'\n'` means the line ended right there and nothing was lost; anything else means the rest of the line is still queued, so drain to the next newline and reject
- Validate the length and reject before copying rather than truncating; a truncated value is a different value the caller then treats as real
- Prefer one bounded `snprintf(dest, sizeof dest, "%s%s", a, b)` over `strcpy` followed by `strcat` - it bounds both operands and the terminator in a single call and reports the length it would have needed, so truncation is detectable via `written < 0 || (size_t)written >= sizeof dest`
- `strncpy` sized from the source (`strlen(user_input)`) is not a fix, and it does not NUL-terminate when the source fills the length argument; an explicit `buf[size - 1] = '\0'` is required every time
- `strncat(dest, src, n)` takes the space *remaining*, not the buffer's capacity - `strncat(dest, src, sizeof dest)` is the standard way to overflow while believing the call is bounded. The correct third argument is `sizeof(dest) - strlen(dest) - 1`
- `sizeof(buffer)` is the array's size only in the scope where the array was declared; after it is passed as a parameter it decays to a pointer and yields 4 or 8, so pass the capacity explicitly
- Bound a manual copy loop by both ends - `i < sizeof(local) - 1 && i < data_len` - since the destination bound alone still reads past the source
- `-fstack-protector-strong` and `-D_FORTIFY_SOURCE` are hardening, not the fix: level 2 catches overflows only where the compiler can size the destination statically, level 3 (GCC 12+/Clang 9+) also covers sizes known only as a runtime expression, and a canary turns the overflow into an abort at function return rather than preventing the write in the first place
- Whether that abort is what actually happens depends on the build, not the source: `-fstack-protector-strong` is Ubuntu's compiler default and is applied by Debian/Fedora/RHEL to their own packages, but not necessarily to a binary a developer compiles by hand on the same machine, and upstream GCC enables it nowhere. Triage on whether the overflow exists rather than on whether a specific build's canary happens to catch it

## Taint Sinks

`gets()`, `strcpy()`, `strcat()`, `sprintf()`, `vsprintf()`, `memcpy()` with an unvalidated length, `scanf("%s", ...)`

## Remediation Steps

- Locate - search for `gets`, `strcpy`, `strcat`, `sprintf`, and index/pointer loops writing into a local array
- Trace data flow - identify where the source data comes from (stdin, network, argv, a file) and whether its length is ever compared against the destination's capacity
- Identify the unsafe pattern - a copy or format whose size is determined by the source rather than the destination, or a loop bound with `<=`
- Replace with the safe pattern - `fgets` for line input, `snprintf` for formatting and concatenation, `memcpy` after an explicit length check
- Bind, encode, validate, or authorize - reject input where `len >= sizeof(dest)` instead of truncating, and report the rejection
- Harden configuration - build with `-fstack-protector-strong` and `-D_FORTIFY_SOURCE=3` at `-O1` or higher (glibc activates it only when `__OPTIMIZE__` is set, so at `-O0` it silently does nothing; needs GCC 12+ with glibc 2.35+, or Clang 9+ with glibc 2.33+, fall back to `=2` on older toolchains)
- Test - run under `-fsanitize=address,undefined` with normal, exactly-capacity, and oversized input, and confirm from the sanitizer output that no out-of-bounds write occurred rather than that nothing visibly crashed
