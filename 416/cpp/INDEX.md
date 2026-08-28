# CWE-416: Use After Free - C++

## LLM Guidance

Use-after-free in C++ is any access through a pointer, reference, iterator or view after the object has been destroyed - directly through a dangling raw pointer, or indirectly through a container entry, callback capture, or alias that outlived the owner. Tie lifetime to a scope or to reference-counted ownership with `std::unique_ptr`/`std::shared_ptr`, and make every non-owning alias either shorter-lived than what it refers to or a `std::weak_ptr` that can be asked. Most current-C++ instances are the second half: the owner is correct and something is still looking at the object through a view that outlived it.

## Key Principles

- Smart pointers guarantee only the accesses made *through* them: `get()`, a reference to `*ptr`, an iterator into an owned container, a `std::string_view` or `std::span` are all raw aliases the owner knows nothing about
- `unique_ptr` names a single owner and moving it leaves the source null, so no second pointer can reach the object after release; `shared_ptr` keeps the object alive while any owner holds it, so an alias made by copying it is an owner rather than a hostage
- Use `std::weak_ptr` for an observer that may outlive the object, and `lock()` at the point of use so the check and the access cannot be separated
- `reset()` leaves the smart pointer null, so an accidental later dereference faults immediately instead of corrupting memory the allocator has reused
- Returning a pointer or reference to a member (`data.data()`, `&vec[0]`) hands out an alias valid only while the owner lives - and a `vector` reallocation invalidates it even while the owner is alive
- The rule for non-owning views (`std::string_view`, `std::span`, references, iterators): a view belongs in a parameter or a short-lived local and nowhere else. Storing one in a member or a container, capturing one in a lambda that is queued, or returning one that outlives the expression it was built from is the dominant shape of this defect in modern C++
- Binding a view to a temporary is the same bug spelled shorter - `std::string_view sv = obj.name() + "!";`, or a view of a `std::string` returned by value, dangles at the end of the full expression, because a view extends nothing
- A lambda capturing by reference, or capturing a raw `this`, outlives the frame it referred to when it is stored in a callback or queue; capture a `shared_ptr` (or `weak_ptr`) instead. Inside a member function that means deriving the class from `std::enable_shared_from_this` and capturing `shared_from_this()` - a bare `this` carries no ownership, and `shared_from_this()` throws `std::bad_weak_ptr` if the object is not already owned by a `shared_ptr`. Where the callback need not be copyable, `std::move_only_function` (C++23) allows a `unique_ptr` to be moved into the capture
- Iterators and references into a container are invalidated by insertion, erasure, or reallocation - not only by destruction of the container
- Build tests with `-fsanitize=address` and the standard library's hardened mode; Valgrind is a useful independent check

## Taint Sinks

Dereference of a raw pointer obtained from `get()`/`release()`, a stored iterator or reference into a container, `std::string_view`/`std::span` outliving its owner, a lambda's captured reference or `this`, a raw `this` passed to an asynchronous callback

## Remediation Steps

- Locate - find the release (a `delete`, a `reset()`, a scope exit, a container erase) and every alias to the same object that can be used afterwards
- Trace data flow - identify aliases that escape: stored raw pointers, captured references, iterators kept across mutations, views returned to callers
- Identify the unsafe pattern - an alias whose lifetime is not bounded by its owner's, or an asynchronous callback holding a raw pointer
- Replace with the safe pattern - move ownership into `unique_ptr`/`shared_ptr` (or a value member such as `std::vector`), and convert escaping observers to `weak_ptr` with `lock()` at the point of use
- Bind, encode, validate, or authorize - re-acquire an iterator or pointer after any operation that can invalidate it, rather than reusing one taken before
- Harden configuration - build and test with `-fsanitize=address`, `-D_GLIBCXX_ASSERTIONS` (or the libc++/MSVC equivalent), which also catches invalidated-iterator use
- Test - exercise the path where the owner is released while an observer is still registered, and confirm the observer's access is refused rather than performed
