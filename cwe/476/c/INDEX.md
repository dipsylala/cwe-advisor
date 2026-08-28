# CWE-476: NULL Pointer Dereference - C

## LLM Guidance

Dereferencing a null pointer in C is undefined behaviour, not a guaranteed crash, and that
distinction drives the fix. Because the standard permits the compiler to assume a dereferenced
pointer was non-null, a null check written *after* the first dereference can be deleted as
provably-true dead code at optimisation levels the release build uses - the guard is present in the
source and absent from the binary. Fix by checking before the first use, checking the return of
every allocation and lookup that can fail, and not relying on `assert` to do it.

## Key Principles

- Order matters more than presence: the check must precede the first dereference. A function that
  does `x = p->field;` and then `if (p == NULL) return;` is not merely redundant - the compiler may
  remove the check because the earlier dereference already licensed the assumption that `p` is
  non-null. This is a real defect class, not a theoretical one; the Linux `tun` driver's
  CVE-2009-1897 is the canonical instance
- Do not rely on `-fno-delete-null-pointer-checks` to make the pattern safe. It exists, and hardened
  builds such as the Linux kernel's use it, but a fix that depends on a compiler flag being present
  in every build configuration is not a fix to the code
- Check every allocation return - `malloc`, `calloc`, `realloc`, `strdup`, `aligned_alloc` - before
  use. `realloc` returning null leaves the *original* block valid, so assigning its result straight
  back to the only surviving pointer both loses the block and creates the null
- Check every lookup and parse that reports absence with null: `fopen`, `getenv`, `strchr`, `strstr`,
  `dlopen`, `dlsym`. `getenv` returning null for an unset variable is the routine case, not the
  exceptional one
- `assert(p != NULL)` is not a runtime check. `NDEBUG` in the release build compiles it out entirely,
  so a codebase that guards with `assert` alone has no check where it matters. Use `assert` to
  document an invariant the caller must uphold, alongside a real check on any value that can be null
  at runtime
- A null check that returns a default and continues can be worse than the crash: if the caller then
  operates on a zeroed or partially-initialised structure, an obvious failure becomes silent wrong
  behaviour. Return an error the caller must handle
- Fix at the producer where several callers share it: a function that returns null on failure has a
  contract, and patching only the call site the scanner reported leaves the siblings exposed
- `memcpy`, `strcpy`, `snprintf` and friends have undefined behaviour on a null pointer argument even
  with a zero length, so a "harmless" zero-length copy through a null pointer is still a defect

## Taint Sinks

`p->field` and `*p` on any pointer from `malloc`/`calloc`/`realloc`/`strdup`, `fopen`, `getenv`,
`strchr`/`strstr`/`strtok`, `dlopen`/`dlsym`, a function documented to return `NULL` on failure, and
pointer arguments to `memcpy`/`strcpy`/`strlen`/`snprintf`

## Remediation Steps

- Locate - identify the exact dereference that faults and the pointer holding null
- Trace data flow - follow that pointer back through assignments, parameters and return values to
  every point it can become null, including allocation failure and a lookup miss
- Identify the unsafe pattern - decide whether the check is missing entirely, present but after the
  first dereference, or present only as an `assert` that `NDEBUG` removes
- Replace the unsafe pattern - move or add the check so it runs before any use of the pointer, and
  handle absence by returning an error rather than substituting a default and continuing
- Bind, encode, validate, or authorize - assign `realloc`'s result to a temporary, check it, and only
  then overwrite the original pointer, so a failure does not leak the block it left valid
- Audit sibling call sites - if the null-producing function has other callers, confirm each handles
  the case; the reported one is rarely the only one
- Harden configuration - build with `-Wnull-dereference`, and run the path under a sanitizer or static
  analyser that models null propagation across functions
- Test - exercise the path with the allocation failing and the lookup missing, and confirm a
  controlled error rather than a crash or a continued run on zeroed data
