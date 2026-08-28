# CWE-401: Missing Release of Memory After Effective Lifetime - C++

## LLM Guidance

C++ has no garbage collector, so memory allocated with `new`/`malloc` and never released accumulates until the process is exhausted, and an exception thrown between the allocation and the `delete` skips the release entirely. The fix is RAII: an owning type whose destructor performs the release, so every path out of the scope - including an exception - frees what it allocated. Use `std::make_unique`/`std::make_shared` and standard containers rather than raw `new`/`delete` and manual arrays.

## Key Principles

- Prefer `std::unique_ptr` for single ownership and `std::shared_ptr` only where ownership is genuinely shared; the destructor is the release, so there is no path that skips it
- Use `std::make_unique`/`std::make_shared` rather than bare `new` - they are exception-safe in argument evaluation and keep the allocation and the owner inseparable
- Use `std::vector`/`std::string` instead of `new[]`; the container owns its storage and grows correctly
- A class that holds a raw owning pointer needs the rule of five (destructor plus all four copy/move operations); a class whose members own themselves needs none of them - the rule of zero, and the reason to change the member type
- Break `shared_ptr` cycles with `std::weak_ptr` on the back-reference: two objects holding `shared_ptr` to each other never reach a zero count and never release
- Release in the destructor rather than in a `catch`: a `delete` in an exception path is skipped by any other path out of the function
- Match the allocator to the deallocator (`new`/`delete`, `new[]`/`delete[]`, `malloc`/`free`) - a mismatch is undefined behaviour, not merely a leak
- For a C API that returns an allocated handle, wrap it in a `unique_ptr` with a custom deleter (`std::unique_ptr<FILE, decltype(&std::fclose)>`, constructed with the free function as its second argument) rather than remembering to call the free function
- Diagnose with `-fsanitize=address,leak` or Valgrind rather than by inspection; both report the allocation stack of what was never freed

## Taint Sinks

`new`/`new[]` without a matching owner, `malloc()`/`calloc()`/`strdup()`, a C API handle-returning call (`fopen`, `sqlite3_open`, `curl_easy_init`), a raw owning pointer member, `shared_ptr` cycles

## Remediation Steps

- Locate - find raw `new`/`malloc` and C API acquisitions whose release is a separate statement
- Trace data flow - identify every path out of the scope, including exceptions and early returns, and check whether the release is on all of them
- Identify the unsafe pattern - a manual release, a raw owning pointer member, or a `shared_ptr` cycle
- Replace with the safe pattern - a `unique_ptr` (with a custom deleter for C handles), a container, or a `weak_ptr` back-reference
- Bind, encode, validate, or authorize - bound any container sized from input so a client cannot drive unbounded growth
- Harden configuration - build tests with `-fsanitize=address,leak` and run the suite under Valgrind in CI
- Test - exercise the failure and exception paths, not just the happy path, and confirm the leak checker reports nothing outstanding
