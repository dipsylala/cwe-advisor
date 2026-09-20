# CWE-122: Heap-based Buffer Overflow

## LLM Guidance

A heap-based buffer overflow writes past the end of a buffer obtained from an allocator - `malloc`, `calloc`, `realloc`, `new[]`, or a container's internal storage - rather than one living in a stack frame. The missing check and the fix are the same as any other out-of-bounds write, so the remediation, taint sinks and safe replacement APIs are CWE-787's and this entry does not repeat them. What differs is what gets corrupted and therefore what finds the bug: there is no saved return address or stack canary next to the buffer, so the damage lands in allocator metadata or in a neighbouring allocation, and a build that would have aborted on a stack smash runs on quietly. Use this entry for the heap-specific part - the allocation size calculation and the detection strategy - and CWE-787 for the fix itself.

## Key Principles

- Apply CWE-787's guidance for the write itself, in the language file that matches the code; where the destination turns out to be a stack array after all, CWE-121 is the closer entry
- The size calculation is the part that differs, because on the heap it decides how much room exists: an overflow in `count * sizeof(T)` wraps to a small allocation that the following loop then overruns, so check `count > SIZE_MAX / sizeof(T)` before multiplying, or use `calloc()`/`reallocarray()`, which perform that check internally
- `realloc` shrinks as well as grows, and a cached pointer or length taken before the call describes the old allocation; re-read both afterwards, and note that on failure `realloc` returns null while leaving the original block valid
- Stack protections do not apply here: `-fstack-protector-strong` guards saved registers and return addresses in a frame, so a heap overflow passes it untouched. The detection that does apply is AddressSanitizer (`-fsanitize=address`), which places redzones around allocations, plus the allocator's own consistency checks - glibc's `MALLOC_CHECK_`/tcache checks turn some corruption into an abort rather than silent progress
- A heap overflow often reports far from its cause, because the corrupted allocation may not be read until much later; treat the reported crash site as the symptom and the write as the thing to find
- MITRE marks CWE-122 usable for mapping at the Variant level, so a finding filed here stays here - unlike its Pillar and Class ancestors, it does not need re-filing

## Remediation Steps

- Locate - identify the destination buffer and confirm it is an allocation (`malloc`/`calloc`/`realloc`/`new[]`, or a container's heap storage) rather than a local array
- Route the fix - apply CWE-787's remediation and its language-specific entry for the write itself; that is where the bounds check and the safe replacement call live
- Check the allocation arithmetic - confirm the size passed to the allocator cannot wrap, and that every later write is bounded by the size actually allocated rather than the size intended
- Re-derive pointers and lengths after any `realloc`, and handle its null return without losing the original block
- Test - build with `-fsanitize=address` and exercise normal, exactly-capacity and oversized inputs, confirming from the sanitizer's report that no out-of-bounds write occurred rather than that the program did not crash
