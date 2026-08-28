# CWE-476: NULL Pointer Dereference - Java

## LLM Guidance

A `NullPointerException` in Java is a caught crash rather than undefined behaviour, so the risk is
availability and the occasional half-completed state change rather than memory corruption. The
distinctive Java cases are the ones where no dereference is visible in the source: unboxing a null
`Integer` in arithmetic or a ternary, and a `Map.get` miss flowing into a numeric expression. Fix by
making absence explicit in the producer's type - `Optional`, a documented empty value, or a
`requireNonNull` at the boundary - rather than adding a null check where the stack trace pointed.

## Key Principles

- Unboxing is an invisible dereference: `int total = counts.get(key);` throws when the key is absent,
  and the line contains no `.` to suggest it. Any arithmetic, comparison, or assignment mixing a
  boxed wrapper with a primitive is a dereference of that wrapper
- The conditional operator applies binary numeric promotion when one branch is a primitive and the
  other a boxed wrapper, which makes the *whole expression* primitive-typed. So
  `Integer result = flag ? 0 : nullInteger;` unboxes the selected branch and throws when `flag` is
  false - at a line whose declared types are all references. Only the chosen branch is evaluated, so
  the untaken one is harmless; the surprise is that unboxing happens at all despite the assignment
  target being `Integer`. Give both branches the same reference type, or test for null first
- `Map.get` returning null is ambiguous between "absent" and "present and mapped to null" - use
  `containsKey`, `getOrDefault`, or `Optional.ofNullable` so the two are distinguishable rather than
  guessing from the null
- Use `Optional` as a return type for a lookup that can legitimately find nothing, and do not call
  `.get()` on it without `isPresent()`; prefer `orElseThrow`, `orElse`, or `map`. `Optional` as a
  field or parameter type is not the intended use and adds a second null to check
- `Objects.requireNonNull(x, "message")` at the top of a constructor or public method converts a
  distant, confusing NPE into an immediate one that names the argument, and is the right way to
  enforce a contract the type system cannot
- Helpful NullPointerException messages (JEP 358) name the exact subexpression that was null, but
  check the version before relying on one: JDK 14 shipped the feature **off by default**, needing
  `-XX:+ShowCodeDetailsInExceptionMessages`, and it became the default only in JDK 15. On 14 without
  the flag, and on anything earlier, the stack trace gives the line and nothing more
- Autoboxing in collections is a common source: `List<Integer>` and `Map<String, Long>` hold nulls
  that a `List<int>` could not, so a stream or loop summing them fails on the first absent entry
- `String.valueOf(obj)` yields the text `"null"` rather than throwing, so a null passes silently
  through logging and concatenation and surfaces later as bad data instead of an exception
- Fix at the producer where several callers share it: changing a method to return `Optional` or to
  throw surfaces every caller that was ignoring the case, which is the point
- A `catch (NullPointerException e)` around business logic is not a fix - it hides which value was
  absent and usually leaves the operation half-applied

## Taint Sinks

Unboxing of `Integer`/`Long`/`Boolean`/`Double` in arithmetic, comparisons, or a ternary,
`Map.get()`/`List.get()` results used without a presence test, `Optional.get()` without
`isPresent()`, `@Autowired` or injected fields used before initialisation, and any method documented
to return `null` on failure

## Remediation Steps

- Locate - identify the expression that threw; on JDK 15 or later (or 14 with
  `-XX:+ShowCodeDetailsInExceptionMessages`) the helpful NPE message names the exact subexpression
  rather than only the line
- Trace data flow - follow the value back to where it can become null: a map miss, a repository
  finder, an unset optional request field, a deserialized JSON property, or an uninitialised field
- Identify the unsafe pattern - a missing check, an unboxing conversion with no visible dereference, a
  ternary unboxing an untaken branch, or a contract that returns null where the caller cannot tell
  absence from a real value
- Replace the unsafe pattern - change the producer to return `Optional<T>` or to throw, or handle the
  absent case explicitly with `getOrDefault`/`orElseThrow` at the point the value is obtained
- Bind, encode, validate, or authorize - add `Objects.requireNonNull` on constructor and public-method
  arguments that must be present, and validate request-bound fields with `@NotNull` so absence is a
  400 rather than a 500
- Audit sibling call sites - a producer that can return null usually has several callers; confirm each
  handles it rather than fixing only the one that threw
- Harden configuration - enable the build's nullability analysis (`@Nullable`/`@NonNull` annotations
  with an analyser, or the IDE's inspection) so an unchecked path fails the build
- Test - exercise the path with the value absent as well as present, and confirm a controlled response
  rather than an exception surfacing as a 500
