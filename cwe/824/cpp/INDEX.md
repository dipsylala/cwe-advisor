# CWE-824: Access of Uninitialized Pointer - C++

## LLM Guidance

A raw pointer member has the same uninitialized-by-default behaviour as in C: a class whose constructor does not set it on every path holds garbage until it is assigned, and the destructor may then `delete` a random address. Modern C++ removes most of this structurally - a default member initializer gives every pointer a defined value on every constructor path including ones added later, and a smart pointer's default state is null, checkable, and safely destructible.

## Key Principles

- Give every pointer and scalar member a default member initializer (`= nullptr`, or a smart pointer that defaults to null), so `T x;`, `T x{}`, `new T` and `new T()` all produce the same fully-initialized object
- Prefer `std::unique_ptr`/`std::shared_ptr` to a raw owning pointer: a member some future constructor forgets to mention is then null rather than garbage, and the implicit destructor releasing it is a no-op instead of a `delete` of a random address
- Assign in the member initializer list rather than the constructor body - members are initialized in declaration order before the body runs, so they hold their final values from the first statement, and the class keeps working when a member is `const`, a reference, or has no default constructor
- Exception safety comes from the member *type*, not from where you assign: with `unique_ptr` members, a throw during the second initialization destroys the first correctly whether you used the list or the body
- The case where it is not cosmetic is a raw owning pointer: `new` for two raw members leaks the first if the second throws, whether written in the body or the list. The fix there is the member type
- Beware the window at the top of a constructor body where members are null but `this` is already a valid object that could be handed to a helper
- Do not add a two-phase `init()` that leaves the object usable before it is complete; construct fully or throw
- Build with `-Wall -Wextra -Wuninitialized` and test under `-fsanitize=memory` or Valgrind

## Taint Sinks

Dereference of a raw pointer member not set on all constructor paths, `delete` in a destructor of such a member, a member used before an `init()` call, `reinterpret_cast` of an uninitialized pointer

## Remediation Steps

- Locate - find raw pointer members and check every constructor, including implicitly generated and delegating ones, for a path that leaves them unset
- Trace data flow - identify uses reachable before assignment, including from the destructor and from helpers called inside the constructor body
- Identify the unsafe pattern - a constructor overload that omits a member, a two-phase `init()`, or a member assigned only inside a conditional
- Replace with the safe pattern - convert owning members to `std::unique_ptr`, give every member a default member initializer, and construct in the member initializer list
- Bind, encode, validate, or authorize - where a member is genuinely optional, express that with `std::optional` or a null smart pointer and check before use rather than leaving it undefined
- Harden configuration - enable the uninitialized-use warnings as errors and build tests with the sanitizers
- Test - construct through every constructor including the default one, destroy without calling any setup method, and confirm under the sanitizers that no uninitialized value is read
