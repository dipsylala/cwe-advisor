# CWE-134: Use of Externally-Controlled Format String - C

## LLM Guidance

`printf`, `fprintf`, `sprintf`, `snprintf` and `syslog` treat their format argument as a template of conversion specifiers. When untrusted input reaches that argument - `printf(user_input)` rather than `printf("%s", user_input)` - the attacker chooses how many arguments the function consumes and what it does with them. `%s` dereferences a value that was never a pointer; `%n` writes the byte count so far through the corresponding argument, which is a direct arbitrary-write primitive. The fix is that the format argument is always a compile-time string literal, at every call site rather than only the one the scan named.

## Key Principles

- The format argument must be a literal; untrusted data goes in the argument list
- `%n` is the reason this class is severe rather than merely a disclosure bug - it turns a log call into an arbitrary memory write
- Leak payloads use positional specifiers (`%7$x`) rather than repeated `%x`: on the x86-64 System V ABI, integer/pointer conversions read from `RSI, RDX, RCX, R8, R9` (`RDI` holds the format string itself) before anything comes off the stack, so the "walks the stack word by word" description is a 32-bit one - a floating-point conversion (`%f`) draws from the separate `XMM0`-`XMM7` bank instead and does not consume one of those five slots
- Use `snprintf` rather than `sprintf` at the same time, which bounds the write and addresses CWE-787 at the same call site
- Where a format genuinely varies, select it from a fixed table of literals by key - never build it from input
- Disable `%n` where the platform allows it (`_FORTIFY_SOURCE >= 2` refuses `%n` in a writable format string on glibc - level 1 does not cover it, and level 3 keeps it; Windows CRT disables it by default) as a hardening layer, not the fix
- Compile with `-Wformat -Wformat-security -Werror`; note `-Wformat-security` fires on a non-literal format with *no* arguments, so pair it with `-Wformat-nonliteral` where a call passes arguments too
- The same rule covers `syslog`, `err`/`warn`, and any project-local variadic wrapper - annotate wrappers with `__attribute__((format(printf, n, m)))`, where `n` is the format argument's position and `m` the first variadic argument's, so the compiler checks their call sites. For a `va_list`-based wrapper with no individual varargs to check, use `m = 0` to validate only the format string itself

## Taint Sinks

`printf()`, `fprintf()`, `sprintf()`, `snprintf()`, `vprintf()`/`vsnprintf()`, `syslog()`, `err()`/`warn()`, custom variadic logging wrappers

## Remediation Steps

- Locate - find calls whose format argument is a variable rather than a literal, including through wrapper functions
- Trace data flow - determine whether that variable can carry request, file, environment, or argv data
- Identify the unsafe pattern - a non-literal format argument, or a format built by concatenation
- Replace with the safe pattern - move the data to the argument list behind a literal `"%s"`
- Bind, encode, validate, or authorize - where the format must vary, look it up from a fixed allowlist of literals by an enum or key
- Harden configuration - build with `-Wformat -Wformat-security -Wformat-nonliteral -Werror` and `-D_FORTIFY_SOURCE=3` at `-O2` or higher (GCC 12+ with glibc 2.35+, or Clang 9+ with glibc 2.33+; fall back to `=2` on older toolchains, which still catches `%n` in writable memory), and annotate variadic wrappers with the `format` attribute
- Test - pass `%x%x%x%x`, `%7$x`, `%n`, and `%2000000000s` through every logging and message path and confirm they are printed literally rather than interpreted
