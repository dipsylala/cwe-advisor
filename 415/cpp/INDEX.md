# CWE-415: Double Free - C++

## LLM Guidance

Double free in C++ is `delete`/`delete[]` (or a `free()` reached from C++ code) running twice on the same pointer, or two owners each believing they must release the same resource. The recurring causes are manual `new`/`delete` pairing, ambiguous ownership in data structures, and cleanup that runs both explicitly and again in a destructor - classically a `catch` block deleting a pointer the `try` block already deleted. Use `std::unique_ptr` for single ownership and `std::shared_ptr` for shared ownership so the release becomes a consequence of the owner's lifetime rather than a call someone has to place correctly.

## Key Principles

- Hold the allocation in an owning member (`std::unique_ptr<char[]>`, `std::vector<char>`) so the class needs no destructor and no `delete` exists to be written twice - this is the rule of zero
- A class holding a raw owning pointer gets a compiler-generated member-wise copy that duplicates the address and gives two destructors one allocation, so it must declare a destructor plus all four copy/move operations - the rule of five. Moving to an owning member type is what avoids that obligation
- `unique_ptr`'s deleted copy constructor propagates: a class with a `unique_ptr` member is non-copyable by default and its move operations are implicitly generated, which is what makes "released exactly once" structural rather than a convention
- Do not wrap an already-owning object in another `make_unique` - the allocation that needs managing is already managed, and the extra indirection buys nothing
- Delete on an error path and again in a destructor is the same defect: give the resource one owner and let the destructor be the only release
- `delete` on a null pointer is defined as a no-op, so nulling after release makes a repeat call harmless, but it protects only the pointer you assign to
- Build tests with `-fsanitize=address`, which names both release stacks, and prefer `std::make_unique`/`std::make_shared` over bare `new`

## Taint Sinks

`delete`, `delete[]`, `free()` called from C++, a hand-written destructor releasing a pointer another path also releases, `release()` on a smart pointer followed by manual deletion

## Remediation Steps

- Locate - find every `delete`/`delete[]`/`free` on the pointer in the finding, including destructors, `catch` blocks, and cleanup helpers
- Trace data flow - establish which object owns the allocation and which paths can reach a release, particularly exception paths and copies of the owner
- Identify the unsafe pattern - two reachable releases, or a copyable class holding a raw owning pointer
- Replace with the safe pattern - convert the member to `std::unique_ptr`/`std::vector` and delete the manual destructor and `delete` calls
- Bind, encode, validate, or authorize - where ownership is genuinely shared, use `std::shared_ptr` so the release happens when the last owner goes away
- Harden configuration - build tests with `-fsanitize=address` and the standard library's hardened mode
- Test - exercise the exception path and the normal path in the same run and confirm ASan reports no double-free; assert that copying or moving the owner does not produce two releases
