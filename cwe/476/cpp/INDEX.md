# CWE-476: NULL Pointer Dereference - C++

## LLM Guidance

C++ inherits C's rule that dereferencing a null pointer is undefined behaviour, including the
consequence that a null check written after the first dereference can be optimised away - read the
`c/` guidance for that and for the allocation-failure cases, which apply unchanged to any C API used
from C++. What C++ adds is a type system that can remove the question entirely: a reference cannot be
null, `std::optional` makes absence explicit and checkable, and smart pointers carry ownership. The
fix is usually to change what the function returns, not to add a guard at the crash site.

## Key Principles

- Express "may be absent" in the type: return `std::optional<T>` for a value that may not exist, take
  a `T&` where the argument is required, and reserve a raw pointer for the genuinely nullable case.
  A guard added to a signature that cannot express absence will be forgotten by the next caller
- `std::optional` moves the failure rather than removing it: `operator*` and `operator->` on an empty
  optional are undefined behaviour exactly like a null dereference, while `.value()` throws
  `std::bad_optional_access`. Use `has_value()`/`if (auto v = f())` or `.value()`, not `*` on an
  unchecked optional
- A reference cannot be null but can dangle, so `*ptr` bound to a `T&` converts a null dereference
  into a harder-to-spot lifetime bug rather than a safe construct. Bind only after the check
- `dynamic_cast` reports failure differently by form: on a pointer it returns `nullptr`, on a
  reference it throws `std::bad_cast`. Code that casts a pointer and uses the result without testing
  is the common instance of this weakness in polymorphic code
- Smart pointers are nullable. A default-constructed or moved-from `std::unique_ptr`/`std::shared_ptr`
  holds null and dereferences exactly as badly; a moved-from pointer is the case reviews miss
- `std::weak_ptr` must be locked and the result tested - `lock()` returns an empty `shared_ptr` when
  the object is gone, which is the designed way to observe expiry, not an exceptional path
- `new` throws `std::bad_alloc` rather than returning null, so a null check on `new` is dead code -
  but `new (std::nothrow)` does return null, and any C allocation reached through an interop layer
  still needs its return checked
- Prefer `.at()` over `operator[]` on maps when absence is possible: `operator[]` on a
  `std::map`/`unordered_map` default-constructs and inserts a value rather than reporting absence,
  which silently changes the container instead of failing
- Where a value is genuinely optional, handle it where it is produced rather than at the crash site;
  the same factory or lookup usually has several callers

## Taint Sinks

`*ptr`/`ptr->` on a raw pointer, smart pointer, or moved-from `unique_ptr`/`shared_ptr`, `*`/`->` on
a `std::optional`, an untested `dynamic_cast<T*>` result, `weak_ptr::lock()` results used unchecked,
`new (std::nothrow)`, and any C API returning `NULL` used through interop

## Remediation Steps

- Locate - identify the dereference that faults and whether the null came from a raw pointer, a smart
  pointer, an empty optional, or a failed `dynamic_cast`
- Trace data flow - follow the value back to where absence originates: a lookup miss, a failed cast, a
  moved-from pointer, an expired `weak_ptr`, or a C API return
- Identify the unsafe pattern - a missing check, a check after first use, `operator*` on an unchecked
  optional, or a signature that cannot express absence so every caller must remember
- Replace the unsafe pattern - change the producer's return type to `std::optional<T>` or a reference
  where presence is guaranteed, and handle absence with an early return or a thrown error
- Bind, encode, validate, or authorize - test `dynamic_cast` pointer results before use, lock and test
  `weak_ptr`, and use `.at()` where an absent key must be an error rather than an insertion
- Audit sibling call sites - a changed return type surfaces every caller that was ignoring the case,
  which is the point; fix them rather than casting the check away
- Harden configuration - enable `-Wnull-dereference` and the analyser's null and optional checks, and
  run the path under UndefinedBehaviorSanitizer
- Test - exercise the absent case for each source, and confirm a controlled error rather than a crash
  or a silently inserted default
