# CWE-1105: Insufficient Encapsulation of Machine-Dependent Functionality - C

## LLM Guidance

C exposes pointer representation, raw memory layout, and the instruction set directly, so machine-dependent assumptions accumulate: a pointer cast to a fixed-width integer, a byte buffer reinterpreted as a multi-byte value without converting byte order, a misaligned multi-byte access, or an instruction-set extension used without checking that the running CPU has it. Each works on the machine it was written on and then breaks - silently or with a fault - on a different word size, endianness, or CPU. The fix is to use the width- and order-explicit types and to confine anything architecture-specific behind one function the rest of the program calls.

## Key Principles

- Round-trip a pointer through `uintptr_t`/`intptr_t`, never `int` or `long` - those truncate on LLP64 and on any platform where pointers are wider. No sanitizer catches this: an explicit `(int)ptr` cast is exactly the form ASan/UBSan treat as intentional, so the real defense is `-Wpointer-to-int-cast` (on by default under `-Wall` when the widths differ) plus `-Wconversion`, not a runtime test. A handle table that only ever stores small integers round-trips fine through the same buggy cast for years - the bug surfaces only once something stores a real pointer in it
- Convert byte order explicitly at every boundary with `ntohl`/`htonl`/`ntohs`/`htons`, or unpack byte by byte for a documented order that is not network order
- Read multi-byte values out of a byte buffer with `memcpy` into a correctly typed local rather than casting the buffer pointer: the cast assumes alignment that faults on some architectures and violates strict aliasing, which the optimiser may act on. Compilers turn the `memcpy` back into a single load where the target allows one
- Declare wire buffers `const uint8_t *`, not `char *`: plain `char`'s signedness is implementation-defined, so a byte from `0x80` upward sign-extends during the shift and corrupts the bytes beneath the top one - the failure looks correct in the high byte, which is the hardest version to debug
- Use `memcpy` for any potentially unaligned access; it is specified to work whatever the alignment and generates whatever sequence the target needs
- Detect CPU features at runtime (`__get_cpuid`, `__builtin_cpu_supports`, MSVC `__cpuid`), not with build-time macros like `#ifdef __AVX2__`, which describe the machine that compiled the binary rather than the one running it
- Guard the architecture-specific *header* as well as the call - `<cpuid.h>` does not exist on ARM, so an unguarded include turns a portability fix into a build failure
- Give every accelerated path an equally correct software fallback, so a CPU without the extension gets a correct result rather than a degraded one
- Replace architecture-specific inline assembly with a portable equivalent; for zeroing secrets, a plain `memset` can be optimised away if the compiler sees the buffer is never read again - use `explicit_bzero` (glibc 2.25+, BSD) or a `volatile` byte loop, which the C standard itself guarantees cannot be elided. `memset_s` is C11 Annex K, which is optional and which glibc does not implement - do not offer it as a Linux fallback. C23's `memset_explicit()` is a portable, standardized option once the target compiles as C23

## Taint Sinks

`(int)`/`(long)` casts of pointers, `*(uint32_t *)buffer` style casts over byte buffers, unaligned multi-byte dereferences, `asm volatile` blocks, `#ifdef` feature guards used as runtime checks, `memset()` intended to erase secrets

## Remediation Steps

- Locate - find pointer-to-integer casts, casts of byte buffers to multi-byte types, inline assembly, and compile-time architecture guards
- Trace data flow - identify where data crosses a machine boundary (network, file, IPC, shared memory) and which representation each side expects
- Identify the unsafe pattern - a truncating integer type, a missing byte-order conversion, an alignment or aliasing assumption, or a feature assumed rather than detected
- Replace with the safe pattern - `uintptr_t` for handles, `memcpy` plus `ntohl`/`htonl` at boundaries, `uint8_t` buffers, and a runtime feature check
- Bind, encode, validate, or authorize - confine every architecture-specific construct to a single function or file so the rest of the program is portable by construction
- Harden configuration - build and test on both a 32-bit and a 64-bit target, and under `-fsanitize=alignment,undefined`
- Test - run the same wire-format tests on a big-endian target (or an emulator), exercise the software fallback path explicitly, and confirm handles survive the integer round-trip on 64-bit
